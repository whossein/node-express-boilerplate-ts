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
  new LocalStrategy({ usernameField: 'username' }, (username, password, done) => {
    User.findOne({ username: username.toLowerCase() })
      .then(async (user) => {
        if (!user) {
          return done(undefined, false, {
            message: `username ${username} not found.`,
          });
        }

        const isMatch = await user.isPasswordMatch(password); // Now TypeScript recognizes this
        if (isMatch) {
          return done(null, user);
        }
      })
      .catch((err) => {
        return done(err, false, {
          message: 'Invalid username or password.',
        });
      });
  }),
);

const options: StrategyOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.jwt.secret,
};

export const jwtStrategy = new JwtStrategy(options, async (payload, done) => {
  try {
    const user = await User.findOne({ username: payload.username });

    if (user) {
      return done(null, user, payload);
    }

    return done(null, false);
  } catch (error) {
    return done(error, false);
  }
});

// passport.use(jwtStrategy);

export default passport;
