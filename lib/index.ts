/**
 * npm dependencies
 */
import * as Boom from 'boom';
import * as assert from 'assert';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as path from 'path';

/**
 * internal dependencies
 */
import { extract, isValid, customOrDefaultKey } from './extract';
const pkg = JSON.parse(String(fs.readFileSync(path.join(__dirname, 'package.json'))));

/**
 * register registers the name and exposes the implementation of the plugin
 * see: http://hapijs.com/api#serverplugins for plugin format
 * @param {Object} server - the hapi server to which we are attaching the plugin
 * @param {Object} options - any options set during plugin registration
 * in this case we are not using the options during register but we do later.
 * @param {Function} next - the callback called once registration succeeds
 * @returns {Function} next - returns (calls) the callback when complete.
 */
export default {
  name: 'hapi-auth-jwt2',
  version: '7.5.0',
  register: (server, options) => {
    server.auth.scheme('jwt', implementation); // hapijs.com/api#serverauthapi
  },
};

/**
 * isFunction checks if a given value is a function.
 * @param {Object} functionToCheck - the object we want to confirm is a function
 * @returns {Boolean} - true if the functionToCheck is a function. :-)
 */
const isFunction = (functionToCheck: any): boolean => {
  return functionToCheck instanceof Function;
};

/**
 * isArray checks if a given variable is an Array.
 * @param {Object} variable - the value we want to confirm is an Array
 * @returns {Boolean} - true if the variable is an Array.
 */
const isArray = (variable: any): boolean => {
  return Array.isArray(variable);
};

/**
 * implementation is the "main" interface to the plugin and contains all the
 * "implementation details" (methods) such as authenicate, response & raiseError
 * @param {Object} server - the Hapi.js server object we are attaching the
 * the hapi-auth-jwt2 plugin to.
 * @param {Object} options - any configuration options passed in.
 * @returns {Function} authenicate - we return the authenticate method after
 * registering the plugin as that's the method that gets called for each route.
 */
const implementation = (server: any, options: any): any => {
  assert(options, 'options are required for jwt auth scheme'); // pre-auth checks
  assert(options.validateFunc
    || options.verifyFunc, 'validateFunc OR verifyFunc function is required!');

  // allow custom error raising or default to Boom if no errorFunc is defined
  function raiseError(errorType, message, scheme?, attributes?) {
    let errorContext = {
      errorType,
      message,
      scheme,
      attributes,
    };

    let _errorType = errorType;   // copies of params
    let _message = message;       // so we can over-write them below
    let _scheme = scheme;         // without a linter warning
    let _attributes = attributes; // if you know a better way please PR!

    if (options.errorFunc && isFunction(options.errorFunc)) {
      errorContext = options.errorFunc(errorContext);

      if (errorContext) {
        _errorType = errorContext.errorType;
        _message = errorContext.message;
        _scheme = errorContext.scheme;
        _attributes = errorContext.attributes;
      }
    }

    return Boom[_errorType](_message, _scheme, _attributes);
  }

  return {
    /**
     * authenticate is the "work horse" of the plugin. it's the method that gets
     * called every time a route is requested and needs to validate/verify a JWT
     * @param {Object} request - the standard route handler request object
     * @param {Object} h - the standard hapi reply interface
     * @returns {Boolean} if the JWT is valid we return a credentials object
     * otherwise throw an error to inform the app & client of unauthorized req.
     */
    authenticate: (request, h) => {
      const token = extract(request, options); // extract token Header/Cookie/Query
      const tokenType = options.tokenType || 'Token'; // see: https://git.io/vXje9
      let decoded;
      let keyFunc;

      if (!token) {
        return raiseError('unauthorized', null, tokenType);
      }

      if (!isValid(token)) { // quick check for validity of token format
        return raiseError('unauthorized', 'Invalid token format', tokenType);
      } // verification is done later, but we want to avoid decoding if malformed
      request.auth.token = token; // keep encoded JWT available in the request
      // otherwise use the same key (String) to validate all JWTs

      try {
        decoded = jwt.decode(token, { complete: options.complete || false });
      } catch (e) { // request should still FAIL if the token does not decode.
        return raiseError('unauthorized', 'Invalid token format', tokenType);
      }

      if (options.key && typeof options.validateFunc === 'function') {
        // if keyFunc is function allow dynamic key lookup: https://git.io/vXjvY
        keyFunc = (isFunction(options.key))
          ? options.key : (decoded_token: any) => {
            return options.key;
          };

        keyFunc(decoded, (err: any, key: any, extraInfo: any) => {
          const verifyOptions = options.verifyOptions || {};
          const keys = (isArray(key)) ? key : [key];
          let keysTried = 0;
          let err_message;

          if (err) {
            return raiseError('wrap', err);
          }
          if (extraInfo) {
            request.plugins[pkg.name] = { extraInfo };
          }

          keys.some((k) => { // itterate through one or more JWT keys
            jwt.verify(token, k, verifyOptions,
              (verify_err, verify_decoded) => {
                if (verify_err) {
                  keysTried++;

                  if (keysTried >= keys.length) {
                    err_message = verify_err.message === 'jwt expired'
                      ? 'Expired token' : 'Invalid token';

                    return h(raiseError('unauthorized',
                      err_message, tokenType), null, { credentials: null });
                  }
                  // There are still other keys that might work

                  // return false;
                } else { // see: http://hapijs.com/tutorials/auth for validateFunc signature

                  return options.validateFunc(verify_decoded, request,
                    (validate_err: boolean, valid: boolean, credentials: any) => { // bring your own checks
                      if (validate_err) {
                        return raiseError('wrap', validate_err);
                      }

                      if (!valid) {
                        h(raiseError('unauthorized',
                          'Invalid credentials', tokenType), null,
                          { credentials: credentials || verify_decoded });

                      } else {
                        h.continue({
                          credentials: credentials || verify_decoded,
                          artifacts: token,
                        });
                      }

                      return false;
                    });
                }

                return false;
              });

            return false;
          });

          return true;
        }); // END keyFunc

      } else { // see: https://github.com/dwyl/hapi-auth-jwt2/issues/130
        return options.verifyFunc(decoded, request,
          (verify_error: boolean, valid: boolean, credentials: any) => {
            if (verify_error) {
              return raiseError('wrap', verify_error);
            }

            if (!valid) {
              h(raiseError('unauthorized', 'Invalid credentials', tokenType), null, { credentials: decoded });
            } else {
              h.continue({
                credentials: credentials || decoded,
                artifacts: token,
              });
            }

            return true;
          });
      }

      return true;
    },

    // payload is an Optional method called if an options.payload is set.
    // cf. https://hapijs.com/tutorials/auth?lang=en_US
    /**
     * response is an Optional method called if an options.responseFunc is set.
     * @param {Object} request - the standard route handler request object
     * @param {Object} h - the standard hapi reply interface ...
     * after we run the custom options.responseFunc we reply.continue to execute
     * the next plugin in the list.
     * @returns {Boolean} true. always return true (unless there's an error...)
     */
    response: (request: any, h: any) => {
      if (options.responseFunc && typeof options.responseFunc === 'function') {
        options.responseFunc(request, h, (err) => {
          if (err) {
            return raiseError('wrap', err);
          } else {
            h.continue();
          }
        });
      } else {
        h.continue();
      }

      return true;
    },
    // allow custom authentication via options.payload
    payload: options.payload, // see: github.com/dwyl/hapi-auth-jwt2/pull/240
  };
};
