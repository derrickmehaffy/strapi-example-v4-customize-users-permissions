// Modules required from the core logic replicated here
const _ = require("lodash");
const utils = require("@strapi/utils");
const { yup, validateYupSchema, sanitize } = utils;
const { ApplicationError, ValidationError, ForbiddenError } = utils.errors;

// Copy function from users-permissions controller file
const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state;
  const userSchema = strapi.getModel("plugin::users-permissions.user");

  return sanitize.contentAPI.output(user, userSchema, { auth });
};

// Extract function that isn't exported by users-permissions plugin to reuse here
// Source: https://github.com/strapi/strapi/blob/develop/packages/plugins/users-permissions/server/controllers/validation/auth.js
const callbackSchema = yup.object({
  identifier: yup.string().required(),
  password: yup.string().required(),
});
const validateCallbackBody = validateYupSchema(callbackSchema);

// ================== Notes ==================
// Several functions have been slightly rewritten here as to not need to pull in some logic we use when building packages
// One of these is the `getService` which we don't really export but basically shortcuts to the `strapi.plugins["users-permissions"].services`
// I've simply replaced it with the full path to the service instead
// The callback function being modified here had it's code pulled from: https://github.com/strapi/strapi/blob/develop/packages/plugins/users-permissions/server/controllers/auth.js
// ================== Notes ==================

module.exports = (plugin) => {
  // Override the callback function from the users-permissions plugin for the providers
  plugin.controllers.auth.callback = async (ctx) => {
    const provider = ctx.params.provider || "local";
    const params = ctx.request.body;

    const store = strapi.store({ type: "plugin", name: "users-permissions" });
    const grantSettings = await store.get({ key: "grant" });

    const grantProvider = provider === "local" ? "email" : provider;

    if (!_.get(grantSettings, [grantProvider, "enabled"])) {
      throw new ApplicationError("This provider is disabled");
    }

    if (provider === "local") {
      await validateCallbackBody(params);

      const { identifier } = params;

      // Check if the user exists.
      const user = await strapi
        .query("plugin::users-permissions.user")
        .findOne({
          where: {
            provider,
            $or: [
              { email: identifier.toLowerCase() },
              { username: identifier },
            ],
          },
        });

      if (!user) {
        throw new ValidationError("Invalid identifier or password");
      }

      if (!user.password) {
        throw new ValidationError("Invalid identifier or password");
      }

      const validPassword = await strapi.plugins["users-permissions"].services[
        "user"
      ].validatePassword(params.password, user.password);

      if (!validPassword) {
        throw new ValidationError("Invalid identifier or password");
      }

      const advancedSettings = await store.get({ key: "advanced" });
      const requiresConfirmation = _.get(
        advancedSettings,
        "email_confirmation"
      );

      if (requiresConfirmation && user.confirmed !== true) {
        throw new ApplicationError("Your account email is not confirmed");
      }

      if (user.blocked === true) {
        throw new ApplicationError(
          "Your account has been blocked by an administrator"
        );
      }

      return ctx.send({
        jwt: strapi.plugins["users-permissions"].services["jwt"].issue({
          id: user.id,
        }),
        user: await sanitizeUser(user, ctx),
      });
    }

    // Connect the user with the third-party provider.
    try {
      const user = await strapi.plugins["users-permissions"].services[
        "providers"
      ].connect(provider, ctx.query);

      if (user.blocked) {
        throw new ForbiddenError(
          "Your account has been blocked by an administrator"
        );
      }

      // ============= Custom logic =============
      // Ability to pass some custom logic here
      console.log("User:", user);
      // ============= Custom logic =============

      return ctx.send({
        jwt: strapi.plugins["users-permissions"].services["jwt"].issue({
          id: user.id,
        }),
        user: await sanitizeUser(user, ctx),
      });
    } catch (error) {
      throw new ApplicationError(error.message);
    }
  };

  return plugin;
};
