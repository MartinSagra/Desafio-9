import passport from "passport";
import local from "passport-local";
import userModel from "../dao/models/usersModel.js";
import GitHubStrategy from "passport-github2";
import { createHash, isValidPassword } from "../utils.js";

const LocalStrategy = local.Strategy;

const initializePassport = () => {
  passport.use(
    "github",
    new GitHubStrategy(
      {
        clientID: "Iv1.bce62f45d89680a5",
        clientSecret: "5ac985af4be39be1787e9eac5b2d79790f025bcd",
        callbackURL: "http://localhost:8080/session/githubcallback",
      },
      async (accessToken, refreshToken, profile, done) => {
       

        try {
          const user = await userModel.findOne({ email: profile._json.email });
          if (user) {
            console.log("User already exits");
            return done(null, user);
          }

          const newUser = {
            user: profile._json.name,
            name: profile._json.name,
            last_name: "",
            email: profile._json.email,
            password: "",
          };
          const result = await userModel.create(newUser);
          return done(null, result);
        } catch (error) {
          return done("error to login with github" + error);
        }
      }
    )
  );

  passport.use(
    "login",
    new LocalStrategy(
      {
        usernameField: "email",
      },
      async (username, password, done) => {
        try {
          const user = await userModel
            .findOne({ email: username })
            .lean()
            .exec();
          if (!user) {
            return done(null, false);
          }
          if (!isValidPassword(user, password)) return done(null, false);
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
  passport.use(
    "register",
    new LocalStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, username, password, done) => {
        let userNew = req.body;
        try {
          const user = await userModel.findOne({ email: username });

          if (user) {
            console.log("Usuario Existente");
            return done(null, false);
          }
          if (
            userNew.email.includes(`_admin`) &&
            userNew.password == "SoyAdminPapa"
          ) {
            let asignarRol = {
              ...userNew,
              rol: "admin",
            };
            userNew = asignarRol;
          } else {
            let asignarRol = {
              ...userNew,
              rol: "user",
            };
            userNew = asignarRol;
          }
          const hashUser = {
            ...userNew,
            password: createHash(userNew.password),
          };
          const result = await userModel.create(hashUser);
          return done(null, result);
        } catch (error) {
          return done("Error al obtener usuario");
        }
      }
    )
  );
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });
  passport.deserializeUser(async (id, done) => {
    const user = await userModel.findById(id);
    done(null, user);
  });
};

export default initializePassport;
