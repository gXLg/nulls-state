const jwt = require("jsonwebtoken");
const { optparser } = require("gxlg-utils");

const parser = optparser([
  { "name": "cookie", "types": ["state"]                   },
  { "name": "jwt",    "types": ["", []],  "required": true },
  { "name": "secure", "types": [true]                      }
]);

module.exports = (opt = {}) => {
  const options = parser(opt);

  const jwtSecret = Buffer.from(options.jwt);
  const DURATION = (24 * 60 * 60 * 1000).toString(); // 1 day

  const plugin = (req, res) => {
    const cookie = req.cookies[options.cookie];
    let s = {};
    try {
      const { state } = jwt.verify(cookie, jwtSecret);
      s = state;
    } catch {}

    req.getState = name => {
      return s[name] ?? null;
    };

    req.popState = name => {
      if (name in s) {
        const v = s[name];
        delete s[name];
        const token = jwt.sign({ "state": s }, jwtSecret, { "expiresIn": DURATION });
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
      const token = jwt.sign({ "state": s }, jwtSecret, { "expiresIn": DURATION });
      const opt = {
        "httpOnly": true,
        "sameSite": true,
        "secure": options.secure
      };
      res.cookie(options.cookie, token, opt);
    };
  };

  return noptions => {
    const prev = noptions.hook;
    noptions.hook = async (req, res) => {
      plugin(req, res);
      await prev(req, res);
    };

    if ("^" in noptions.srcProviders) {
      console.warn("Can't initialize the shorthand state provider: It overwrites an already existing provider.");
    } else {
      noptions.srcProviders["^"] = v => {
        return r => r.popState(v) ?? "";
      };
    }
  };
};
