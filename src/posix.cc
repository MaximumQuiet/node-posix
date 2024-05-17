#include <napi.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h> // setrlimit, getrlimit
#include <limits.h> // PATH_MAX
#include <pwd.h> // getpwnam, passwd
#include <grp.h> // getgrnam, group
#include <syslog.h> // openlog, closelog, syslog, setlogmask

#ifdef __linux__
#  include <sys/swap.h>  // swapon, swapoff
#endif

Napi::Value node_getppid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
        Napi::Error::New(env, "getppid: takes no arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    // on some platforms pid_t is defined as long hence the static_cast
    return Napi::Number::New(env, static_cast<int32_t>(getppid()));
}

Napi::Value node_getpgid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "getpgid: takes exactly one argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsNumber()) {
       Napi::TypeError::New(env, "getpgid: first argument must be an integer").ThrowAsJavaScriptException();
       return env.Null();
    }

    const pid_t pid = info[0].ToNumber();

    // on some platforms pid_t is defined as long hence the static_cast
    return Napi::Number::New(env, static_cast<int32_t>(getpgid(pid)));
}

Napi::Value node_setpgid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::Error::New(env, "setpgid: takes exactly two arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsNumber()) {
        Napi::TypeError::New(env, "setpgid: first argument must be an integer").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[1].IsNumber()) {
        Napi::TypeError::New(env, "setpgid: first argument must be an integer").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (setpgid(info[0].ToNumber(), info[1].ToNumber()) < 0) {
        Napi::Error e = Napi::Error::New(env, "setpgid");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value node_geteuid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
        Napi::Error::New(env, "geteuid: takes no arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    return Napi::Number::New(env, geteuid());
}

Napi::Value node_getegid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
        Napi::Error::New(env, "getegid: takes no arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    return Napi::Number::New(env, getegid());
}

Napi::Value node_setsid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
        Napi::Error::New(env, "setsid: takes no arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    pid_t sid = setsid();

    if (sid == -1) {
        Napi::Error e = Napi::Error::New(env, "setsid");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    // on some platforms pid_t is defined as long hence the static_cast
    return Napi::Number::New(env, static_cast<int32_t>(sid));
}

Napi::Value node_chroot(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "chroot: takes exactly one argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "chroot: first argument must be a string").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string dir_path_str = info[0].As<Napi::String>().Utf8Value();
    const char *dir_path = dir_path_str.data();

    // proper order is to first chdir() and then chroot()
    if (chdir(dir_path)) {
        Napi::Error e = Napi::Error::New(env, "chroot: chdir: ");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    if(chroot(dir_path)) {
        Napi::Error e = Napi::Error::New(env, "chroot");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

struct name_to_int_t {
  const char* name;
  int resource;
};

static const name_to_int_t rlimit_name_to_res[] = {
  { "core", RLIMIT_CORE },
  { "cpu", RLIMIT_CPU },
  { "data", RLIMIT_DATA },
  { "fsize", RLIMIT_FSIZE },
  { "nofile", RLIMIT_NOFILE },
  #ifdef RLIMIT_NPROC
  { "nproc", RLIMIT_NPROC },
    #endif
  { "stack", RLIMIT_STACK },
  #ifdef RLIMIT_AS
  { "as", RLIMIT_AS },
  #endif
  { 0, 0 }
};

// return null if value is RLIM_INFINITY, otherwise the uint value
static Napi::Value rlimit_value(const Napi::Env &env, rlim_t limit) {
    if (limit == RLIM_INFINITY) {
        return env.Null();
    } else {
        return Napi::Number::New(env, (double)limit);
    }
}

Napi::Value node_getrlimit(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "getrlimit: requires exactly one argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "getrlimit: argument must be a string").ThrowAsJavaScriptException();
        return env.Null();
    }

    struct rlimit limit;
    std::string rlimit_name_str = info[0].As<Napi::String>().Utf8Value();
    const char *rlimit_name = rlimit_name_str.data();
    int resource = -1;

    for (const name_to_int_t* item = rlimit_name_to_res; item->name; ++item) {
        if (!strcmp(rlimit_name, item->name)) {
            resource = item->resource;
            break;
        }
    }

    if (resource < 0) {
        Napi::Error::New(env, "getrlimit: unknown resource name").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (getrlimit(resource, &limit)) {
        Napi::Error e = Napi::Error::New(env, "getrlimit");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object data = Napi::Object::New(env);
    (data).Set(Napi::String::New(env, "soft"), rlimit_value(env, limit.rlim_cur));
    (data).Set(Napi::String::New(env, "hard"), rlimit_value(env, limit.rlim_max));

    return data;
}

Napi::Value node_setrlimit(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::Error::New(env, "setrlimit: requires exactly two arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "setrlimit: argument 0 must be a string").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[1].IsObject()) {
        Napi::TypeError::New(env, "setrlimit: argument 1 must be an object").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string rlimit_name_str = info[0].As<Napi::String>().Utf8Value();
    const char *rlimit_name = rlimit_name_str.data();
    int resource = -1;
    for (const name_to_int_t* item = rlimit_name_to_res; item->name; ++item) {
        if (!strcmp(rlimit_name, item->name)) {
            resource = item->resource;
            break;
        }
    }

    if (resource < 0) {
        Napi::Error::New(env, "setrlimit: unknown resource name").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object limit_in = info[1].As<Napi::Object>(); // Cast
    Napi::String soft_key = Napi::String::New(env, "soft");
    Napi::String hard_key = Napi::String::New(env, "hard");
    struct rlimit limit;
    bool get_soft = false, get_hard = false;
    if ((limit_in).Has(soft_key)) {
        if ((limit_in).Get(soft_key).IsNull()) {
            limit.rlim_cur = RLIM_INFINITY;
        } else {
            limit.rlim_cur = limit_in.Get(soft_key).ToNumber().Int64Value();
        }
    } else {
        get_soft = true;
    }

    if ((limit_in).Has(hard_key)) {
        if ((limit_in).Get(hard_key).IsNull()) {
            limit.rlim_max = RLIM_INFINITY;
        } else {
            limit.rlim_max = limit_in.Get(hard_key).ToNumber().Int64Value();
        }
    } else {
        get_hard = true;
    }

    if (get_soft || get_hard) {
        // current values for the limits are needed
        struct rlimit current;
        if (getrlimit(resource, &current)) {
            Napi::Error e = Napi::Error::New(env, "getrlimit");
            e.Set("code", Napi::Number::New(env, errno));
            e.ThrowAsJavaScriptException();
            return env.Null();
        }
        if (get_soft) { limit.rlim_cur = current.rlim_cur; }
        if (get_hard) { limit.rlim_max = current.rlim_max; }
    }

    if (setrlimit(resource, &limit)) {
        Napi::Error e = Napi::Error::New(env, "setrlimit");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value node_getpwnam(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "getpwnam: requires exactly 1 argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    struct passwd* pwd;
    errno = 0; // reset errno before the call

    if (info[0].IsNumber()) {
        pwd = getpwuid(info[0].ToNumber().Int32Value());
        if (errno) {
            Napi::Error e = Napi::Error::New(env, "getpwuid");
            e.Set("code", Napi::Number::New(env, errno));
            e.ThrowAsJavaScriptException();
            return env.Null();
        }
    } else if (info[0].IsString()) {
        std::string pwnam_str = info[0].As<Napi::String>();
        const char *pwnam = pwnam_str.data();
        pwd = getpwnam(pwnam);
        if(errno) {
            Napi::Error e = Napi::Error::New(env, "getpwnam");
            e.Set("code", Napi::Number::New(env, errno));
            e.ThrowAsJavaScriptException();
            return env.Null();
        }
    } else {
        Napi::TypeError::New(env, "argument must be a number or a string").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!pwd) {
        Napi::Error::New(env, "user id does not exist").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object obj = Napi::Object::New(env);
    (obj).Set(Napi::String::New(env, "name"), Napi::String::New(env, pwd->pw_name));
    (obj).Set(Napi::String::New(env, "passwd"), Napi::String::New(env, pwd->pw_passwd));
    (obj).Set(Napi::String::New(env, "uid"), Napi::Number::New(env, pwd->pw_uid));
    (obj).Set(Napi::String::New(env, "gid"), Napi::Number::New(env, pwd->pw_gid));
#ifdef __ANDROID__
    (obj).Set(Napi::String::New(env, "gecos"), env.Null());
#else
    (obj).Set(Napi::String::New(env, "gecos"), Napi::String::New(env, pwd->pw_gecos));
#endif
    (obj).Set(Napi::String::New(env, "shell"), Napi::String::New(env, pwd->pw_shell));
    (obj).Set(Napi::String::New(env, "dir"), Napi::String::New(env, pwd->pw_dir));

    return obj;
}

Napi::Value node_getgrnam(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "getgrnam: requires exactly 1 argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    struct group* grp;
    struct group groupbuf;
    char *buf = NULL;
    char *newbuf;
    int size;
    int rc;

    size = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (size == -1) {
        size = 2048;
    }

    buf = (char*) malloc((size_t) size);
    if (buf == NULL) {
        Napi::Error::New(env, "malloc() failed").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info[0].IsNumber()) {
        while ((rc = getgrgid_r(info[0].ToNumber().Int32Value(), &groupbuf, buf, (size_t) size, &grp)) == ERANGE) {
            size *= 2;
            newbuf = (char*) realloc(buf, (size_t) size);
            if (!newbuf) {
                break;
            }
            buf = newbuf;
        }
        if (rc) {
            free(buf);
            Napi::Error e = Napi::Error::New(env, "getgrgid");
            e.Set("code", Napi::Number::New(env, errno));
            e.ThrowAsJavaScriptException();
            return env.Null();
        }
    } else if (info[0].IsString()) {
        std::string pwnam_str = info[0].As<Napi::String>();
        const char *pwnam = pwnam_str.data();
        while ((rc = getgrnam_r(pwnam, &groupbuf, buf, (size_t) size, &grp)) == ERANGE) {
            size *= 2;
            newbuf = (char*) realloc(buf, (size_t) size);
            if (!newbuf) {
                break;
            }
            buf = newbuf;
        }
        if (rc) {
            free(buf);
            Napi::Error e = Napi::Error::New(env, "getgrnam");
            e.Set("code", Napi::Number::New(env, errno));
            e.ThrowAsJavaScriptException();
            return env.Null();
        }
    } else {
        Napi::TypeError::New(env, "argument must be a number or a string").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!grp) {
        free(buf);
        Napi::Error::New(env, "group id does not exist").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object obj = Napi::Object::New(env);
    (obj).Set(Napi::String::New(env, "name"), Napi::String::New(env, grp->gr_name));
    (obj).Set(Napi::String::New(env, "passwd"), Napi::String::New(env, grp->gr_passwd));
    (obj).Set(Napi::String::New(env, "gid"), Napi::Number::New(env, grp->gr_gid));

    Napi::Array members = Napi::Array::New(env);
    char** cur = grp->gr_mem;
    for (size_t i=0; *cur; ++i, ++cur) {
        (members).Set(i, Napi::String::New(env, *cur));
    }
    (obj).Set(Napi::String::New(env, "members"), members);

    free(buf);
    return obj;
}

Napi::Value node_initgroups(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::Error::New(env, "initgroups: requires exactly 2 arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString() || !info[1].IsNumber()) {
        Napi::Error::New(env, "initgroups: first argument must be a string and the second an integer").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string unam_str = info[0].As<Napi::String>();
    const char *unam = unam_str.data();
    if (initgroups(unam, info[1].ToNumber().Int32Value())) {
        Napi::Error e = Napi::Error::New(env, "initgroups");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value node_seteuid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "seteuid: requires exactly 1 argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (seteuid(info[0].ToNumber().Int32Value())) {
        Napi::Error e = Napi::Error::New(env, "seteuid");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value node_setegid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "setegid: requires exactly 1 argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (setegid(info[0].ToNumber().Int32Value())) {
        Napi::Error e = Napi::Error::New(env, "setegid");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value node_setregid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::Error::New(env, "setregid: requires exactly 2 arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (setregid(info[0].ToNumber().Int32Value(), info[1].ToNumber().Int32Value())) {
        Napi::Error e = Napi::Error::New(env, "setregid");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value node_setreuid(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::Error::New(env, "setreuid: requires exactly 2 arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (setreuid(info[0].ToNumber().Int32Value(), info[1].ToNumber().Int32Value())) {
        Napi::Error e = Napi::Error::New(env, "setreuid");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

// openlog() first argument (const char* ident) is not guaranteed to be
// copied within the openlog() call so we need to keep it in a safe location
static const size_t MAX_SYSLOG_IDENT=100;
static char syslog_ident[MAX_SYSLOG_IDENT+1] = {0};

Napi::Value node_openlog(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 3) {
        Napi::Error::New(env, "openlog: requires exactly 3 arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string ident_str = info[0].As<Napi::String>();
    const char *ident = ident_str.data();
    strncpy(syslog_ident, ident, MAX_SYSLOG_IDENT);
    syslog_ident[MAX_SYSLOG_IDENT] = 0;
    if (!info[1].IsNumber() || !info[2].IsNumber()) {
        Napi::Error::New(env, "openlog: invalid argument values").ThrowAsJavaScriptException();
        return env.Null();
    }
    // note: openlog does not ever fail, no return value
    openlog(syslog_ident, info[1].ToNumber().Int32Value(), info[2].ToNumber().Int32Value());

    return env.Undefined();
}

Napi::Value node_closelog(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
        Napi::Error::New(env, "closelog: does not take any arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    // note: closelog does not ever fail, no return value
    closelog();

    return env.Undefined();
}

Napi::Value node_syslog(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::Error::New(env, "syslog: requires exactly 2 arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string message_str = info[1].As<Napi::String>();
    const char *message = message_str.data();
    // note: syslog does not ever fail, no return value
    syslog(info[0].ToNumber().Int32Value(), "%s", message);

    return env.Undefined();
}

Napi::Value node_setlogmask(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "setlogmask: takes exactly 1 argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    return Napi::Number::New(env, setlogmask(info[0].ToNumber().Int32Value()));
}

#define ADD_MASK_FLAG(name, flag) \
    (obj).Set(Napi::String::New(env, name), Napi::Number::New(env, flag)); \
    (obj).Set(Napi::String::New(env, "mask_" name), Napi::Number::New(env, LOG_MASK(flag)));

Napi::Value node_update_syslog_constants(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::Error::New(env, "update_syslog_constants: takes exactly 1 argument").ThrowAsJavaScriptException();
      return env.Null();
    }

    if (!info[0].IsObject()) {
        Napi::TypeError::New(env, "update_syslog_constants: argument must be an object").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object obj = info[0].As<Napi::Object>();
    ADD_MASK_FLAG("emerg", LOG_EMERG);
    ADD_MASK_FLAG("alert", LOG_ALERT);
    ADD_MASK_FLAG("crit", LOG_CRIT);
    ADD_MASK_FLAG("err", LOG_ERR);
    ADD_MASK_FLAG("warning", LOG_WARNING);
    ADD_MASK_FLAG("notice", LOG_NOTICE);
    ADD_MASK_FLAG("info", LOG_INFO);
    ADD_MASK_FLAG("debug", LOG_DEBUG);

    // facility constants
    (obj).Set(Napi::String::New(env, "auth"), Napi::Number::New(env, LOG_AUTH));
#ifdef LOG_AUTHPRIV
    (obj).Set(Napi::String::New(env, "authpriv"), Napi::Number::New(env, LOG_AUTHPRIV));
#endif
    (obj).Set(Napi::String::New(env, "cron"), Napi::Number::New(env, LOG_CRON));
    (obj).Set(Napi::String::New(env, "daemon"), Napi::Number::New(env, LOG_DAEMON));
#ifdef LOG_FTP
    (obj).Set(Napi::String::New(env, "ftp"), Napi::Number::New(env, LOG_FTP));
#endif
    (obj).Set(Napi::String::New(env, "kern"), Napi::Number::New(env, LOG_KERN));
    (obj).Set(Napi::String::New(env, "lpr"), Napi::Number::New(env, LOG_LPR));
    (obj).Set(Napi::String::New(env, "mail"), Napi::Number::New(env, LOG_MAIL));
    (obj).Set(Napi::String::New(env, "news"), Napi::Number::New(env, LOG_NEWS));
    (obj).Set(Napi::String::New(env, "syslog"), Napi::Number::New(env, LOG_SYSLOG));
    (obj).Set(Napi::String::New(env, "user"), Napi::Number::New(env, LOG_USER));
    (obj).Set(Napi::String::New(env, "uucp"), Napi::Number::New(env, LOG_UUCP));
    (obj).Set(Napi::String::New(env, "local0"), Napi::Number::New(env, LOG_LOCAL0));
    (obj).Set(Napi::String::New(env, "local1"), Napi::Number::New(env, LOG_LOCAL1));
    (obj).Set(Napi::String::New(env, "local2"), Napi::Number::New(env, LOG_LOCAL2));
    (obj).Set(Napi::String::New(env, "local3"), Napi::Number::New(env, LOG_LOCAL3));
    (obj).Set(Napi::String::New(env, "local4"), Napi::Number::New(env, LOG_LOCAL4));
    (obj).Set(Napi::String::New(env, "local5"), Napi::Number::New(env, LOG_LOCAL5));
    (obj).Set(Napi::String::New(env, "local6"), Napi::Number::New(env, LOG_LOCAL6));
    (obj).Set(Napi::String::New(env, "local7"), Napi::Number::New(env, LOG_LOCAL7));

    // option constants
    (obj).Set(Napi::String::New(env, "pid"), Napi::Number::New(env, LOG_PID));
    (obj).Set(Napi::String::New(env, "cons"), Napi::Number::New(env, LOG_CONS));
    (obj).Set(Napi::String::New(env, "ndelay"), Napi::Number::New(env, LOG_NDELAY));
    (obj).Set(Napi::String::New(env, "odelay"), Napi::Number::New(env, LOG_ODELAY));
    (obj).Set(Napi::String::New(env, "nowait"), Napi::Number::New(env, LOG_NOWAIT));

    return env.Undefined();
}

Napi::Value node_gethostname(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
        Napi::Error::New(env, "gethostname: takes no arguments").ThrowAsJavaScriptException();
        return env.Null();
    }
#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 255
#endif

    char hostname[HOST_NAME_MAX];

    int rc = gethostname(hostname, HOST_NAME_MAX);
    if (rc != 0) {
        Napi::Error e = Napi::Error::New(env, "gethostname");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return Napi::String::New(env, hostname);
}

#ifndef __ANDROID__
Napi::Value node_sethostname(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "sethostname: takes exactly 1 argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "sethostname: first argument must be a string").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string hostname_str = info[0].As<Napi::String>();
    const char *hostname = hostname_str.data();

    int rc = sethostname(hostname, hostname_str.length());
    if (rc != 0) {
        Napi::Error e = Napi::Error::New(env, "sethostname");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}
#endif // __ANDROID__

#ifdef __linux__
Napi::Value node_swapon(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::Error::New(env, "swapon: takes exactly 2 argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "swapon: first argument must be a string").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[1].IsNumber()) {
        Napi::TypeError::New(env, "swapon: second argument must be an integer").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string str_str = info[0].As<Napi::String>();
    const char *str = str_str.data();

    int rc = swapon(str, info[1].ToNumber().Int32Value());
    if (rc != 0) {
        Napi::Error e = Napi::Error::New(env, "swapon");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value node_swapoff(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::Error::New(env, "swapoff: takes exactly 1 argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "swapoff: first argument must be a string").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string str_str = info[0].As<Napi::String>();
    const char *str = str_str.data();

    int rc = swapoff(str);
    if (rc != 0) {
        Napi::Error e = Napi::Error::New(env, "swapoff");
        e.Set("code", Napi::Number::New(env, errno));
        e.ThrowAsJavaScriptException();
        return env.Null();
    }

    return env.Undefined();
}

Napi::Value node_update_swap_constants(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::Error::New(env, "update_syslog_constants: takes exactly 1 argument").ThrowAsJavaScriptException();
      return env.Null();
    }

    if (!info[0].IsObject()) {
        Napi::TypeError::New(env, "update_syslog_constants: argument must be an object").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object obj = info[0].As<Napi::Object>();
    (obj).Set(Napi::String::New(env, "prefer"), Napi::Number::New(env, SWAP_FLAG_PREFER));
#ifdef SWAP_FLAG_DISCARD
    (obj).Set(Napi::String::New(env, "discard"), Napi::Number::New(env, SWAP_FLAG_DISCARD));
#endif // SWAP_FLAG_DISCARD

    return env.Undefined();
}
#endif // __linux__

Napi::Object init(Napi::Env env, Napi::Object exports) {
  exports.Set("getppid", Napi::Function::New(env, node_getppid));
  exports.Set("getpgid", Napi::Function::New(env, node_getpgid));
  exports.Set("setpgid", Napi::Function::New(env, node_setpgid));
  exports.Set("geteuid", Napi::Function::New(env, node_geteuid));
  exports.Set("getegid", Napi::Function::New(env, node_getegid));
  exports.Set("setsid", Napi::Function::New(env, node_setsid));
  exports.Set("chroot", Napi::Function::New(env, node_chroot));
  exports.Set("getrlimit", Napi::Function::New(env, node_getrlimit));
  exports.Set("setrlimit", Napi::Function::New(env, node_setrlimit));
  exports.Set("getpwnam", Napi::Function::New(env, node_getpwnam));
  exports.Set("getgrnam", Napi::Function::New(env, node_getgrnam));
  exports.Set("initgroups", Napi::Function::New(env, node_initgroups));
  exports.Set("seteuid", Napi::Function::New(env, node_seteuid));
  exports.Set("setegid", Napi::Function::New(env, node_setegid));
  exports.Set("setregid", Napi::Function::New(env, node_setregid));
  exports.Set("setreuid", Napi::Function::New(env, node_setreuid));
  exports.Set("openlog", Napi::Function::New(env, node_openlog));
  exports.Set("closelog", Napi::Function::New(env, node_closelog));
  exports.Set("syslog", Napi::Function::New(env, node_syslog));
  exports.Set("setlogmask", Napi::Function::New(env, node_setlogmask));
  exports.Set("update_syslog_constants", Napi::Function::New(env, node_update_syslog_constants));
  exports.Set("gethostname", Napi::Function::New(env, node_gethostname));
  #ifndef ANDROID
    exports.Set("sethostname", Napi::Function::New(env, node_sethostname));
  #endif // ANDROID

  #ifdef linux
    exports.Set("swapon", Napi::Function::New(env, node_swapon));
    exports.Set("swapoff", Napi::Function::New(env, node_swapoff));
    exports.Set("update_swap_constants", Napi::Function::New(env, node_update_swap_constants));
  #endif

  return exports;
}

NODE_API_MODULE(posix, init);
