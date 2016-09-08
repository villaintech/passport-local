/**
 * Module dependencies.
 */
const passport = require('passport-strategy')
  , util = require('util');


/**
 * `Strategy` constructor.
 *
 * This anonymous authentication strategy authenticates passes credentials
 * and implements ip logging.
 *
 * Applications must supply a `logging` callback which accepts the request object (for ip logging, from headers), and then
 * calls the `done` callback supplying a `user`, which should be set to `false` if the ip logging failed.
 * If an exception occurred, `err` should be set.
 * 
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.

 *
 * Examples:
 *
 *     passport.use(new LocalStrategy(
 *       function(req, logged) {
 *         User.findOne({ req.get("X-Real-IP") }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Function} logging
 * @api public
 */
function Strategy(logger) {
  if (!logging) { throw new TypeError('AnonStrategy requires a logging callback'); }
  
  passport.Strategy.call(this);
  this.name = 'anonymous';
  this._logger = logger;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  let self = this;
  
  function logged(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  
  try {
      this._logger(req, logged);
  } catch (ex) {
    return self.error(ex);
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
