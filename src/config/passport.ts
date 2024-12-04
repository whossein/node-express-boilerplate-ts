import passport from 'passport';
import passportLocal from 'passport-local';
// import passportApiKey from "passport-headerapikey";
import passportJwt from 'passport-jwt';
import { IUser, User } from '../models';
import config from './config';
import { StrategyOptions } from 'passport-jwt';
import { Request } from 'express';

const LocalStrategy = passportLocal.Strategy;
const JwtStrategy = passportJwt.Strategy;
const ExtractJwt = passportJwt.ExtractJwt;

passport.use(
  new LocalStrategy(
    { usernameField: 'username' },
    (username, password, done) => {
      User.findOne(
        { username: username.toLowerCase() },
        (err: any, user: any) => {
          if (err) {
            return done(err);
          }
          if (!user) {
            return done(undefined, false, {
              message: `username ${username} not found.`,
            });
          }
          user.comparePassword(password, (err: Error, isMatch: boolean) => {
            if (err) {
              return done(err);
            }
            if (isMatch) {
              return done(undefined, user);
            }
            return done(undefined, false, {
              message: 'Invalid username or password.',
            });
          });
        },
      );
    },
  ),
);

// passport.use(
//   new JwtStrategy(
//     {
//       jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
//       secretOrKey: config.jwt.secret,
//     },
//     function (jwtToken, done) {
//       User.findOne(
//         { username: jwtToken.username },
//         function (err: any, user: IUser) {
//           if (err) {
//             return done(err, false);
//           }
//           if (user) {
//             return done(undefined, user, jwtToken);
//           } else {
//             return done(undefined, false);
//           }
//         },
//       );
//     },
//   ),
// );

const options: StrategyOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.jwt.secret,
};

export const jwtStrategy = new JwtStrategy(options, async (payload, done) => {
  try {
    const user = User.findOne(
      { username: payload.username },
      function (err: any, user: IUser) {
        if (err) {
          return done(err, false);
        }
        if (user) {
          return done(undefined, user, payload);
        } else {
          return done(undefined, false);
        }
      },
    );

    if (user) {
      return done(null, user);
    }
    return done(null, false);
  } catch (error) {
    return done(error, false);
  }
});

// passport.use(jwtStrategy);

export default passport;
