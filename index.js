const jwt = require("jsonwebtoken");
const { optparser } = require("gxlg-utils");

const parser = optparser([
  { "name": "cookie", "types": ["state"]                   },
  { "name": "secret", "types": [""],      "required": true },
  { "name": "secure", "types": [true]                      }
]);

module.exports = (opt = {}) => {
  const options = parser(opt);

  const DURATION = (24 * 60 * 60 * 1000).toString(); // 1 day

  const plugin = (req, res) => {
    const cookie = req.cookies[options.cookie];
    let s = {};
    try {
      const { state } = jwt.verify(cookie, options.secret);
      s = state;
    } catch {}

    req.getState = name => {
      return s[name] ?? null;
    };

    req.popState = name => {
      if (name in s) {
        const v = s[name];
        delete s[name];
        const token = jwt.sign({ "state": s }, options.secret, { "expiresIn": DURATION });
        const opt = {
          "httpOnly": true,
          "sameSite": true,
          "secure": options.secure
        };
        res.cookie(options.cookie, token, opt);
        return v;
      } else {
        return null;
      }
    }

    res.putState = (name, value) => {
      s[name] = value;
      const token = jwt.sign({ "state": s }, options.secret, { "expiresIn": DURATION });
      const opt = {
        "httpOnly": true,
        "sameSite": true,
        "secure": options.secure
      };
      res.cookie(options.cookie, token, opt);
    };
  };

  return options => {
    const prev = options.hook;
    options.hook = async (req, res) => {
      plugin(req, res);
      await prev(req, res);
    };

    if ("^" in options.srcProviders) {
      console.warn("Can't initialize the shorthand state provider: It overwrites an already existing provider.");
    } else {
      options.srcProviders["^"] = v => {
        return r => r.popState(v) ?? "";
      };
    }
  };
};
