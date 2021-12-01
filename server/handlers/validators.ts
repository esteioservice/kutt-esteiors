import { body, param } from "express-validator";
import { isAfter, subDays, subHours, addMilliseconds } from "date-fns";
import urlRegex from "url-regex";
import { promisify } from "util";
import bcrypt from "bcryptjs";
import axios from "axios";
import dns from "dns";
import URL from "url";
import ms from "ms";

import { CustomError, addProtocol, removeWww } from "../utils";
import query from "../queries";
import knex from "../knex";
import env from "../env";

const dnsLookup = promisify(dns.lookup);

export const preservedUrls = [
  "login",
  "logout",
  "signup",
  "reset-password",
  "resetpassword",
  "url-password",
  "url-info",
  "settings",
  "stats",
  "verify",
  "api",
  "404",
  "static",
  "images",
  "banned",
  "terms",
  "privacy",
  "protected",
  "report",
  "pricing"
];

export const checkUser = (value, { req }) => !!req.user;

export const createLink = [
  body("target")
    .exists({ checkNull: true, checkFalsy: true })
    .withMessage("A URL está faltando.")
    .isString()
    .trim()
    .isLength({ min: 1, max: 2040 })
    .withMessage("O comprimento máximo do URL é 2.040.")
    .customSanitizer(addProtocol)
    .custom(
      value =>
        urlRegex({ exact: true, strict: false }).test(value) ||
        /^(?!https?)(\w+):\/\//.test(value)
    )
    .withMessage("URL não válida.")
    .custom(value => removeWww(URL.parse(value).host) !== env.DEFAULT_DOMAIN)
    .withMessage(`${env.DEFAULT_DOMAIN} URLs are not allowed.`),
  body("password")
    .optional({ nullable: true, checkFalsy: true })
    .custom(checkUser)
    .withMessage("Apenas usuários podem usar este campo.")
    .isString()
    .isLength({ min: 3, max: 64 })
    .withMessage("O comprimento da senha deve estar entre 3 e 64."),
  body("customurl")
    .optional({ nullable: true, checkFalsy: true })
    .custom(checkUser)
    .withMessage("Apenas usuários podem usar este campo.")
    .isString()
    .trim()
    .isLength({ min: 1, max: 64 })
    .withMessage("O comprimento do URL personalizado deve estar entre 1 e 64.")
    .custom(value => /^[a-zA-Z0-9-_]+$/g.test(value))
    .withMessage("URL personalizado não é válido")
    .custom(value => !preservedUrls.some(url => url.toLowerCase() === value))
    .withMessage("Você não pode usar este URL personalizado."),
  body("reuse")
    .optional({ nullable: true })
    .custom(checkUser)
    .withMessage("Apenas usuários podem usar este campo.")
    .isBoolean()
    .withMessage("Reutilizar deve ser booleano."),
  body("description")
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .trim()
    .isLength({ min: 0, max: 2040 })
    .withMessage("O comprimento da descrição deve estar entre 0 e 2040."),
  body("expire_in")
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .trim()
    .custom(value => {
      try {
        return !!ms(value);
      } catch {
        return false;
      }
    })
    .withMessage("O formato de expiração é inválido. Exemplos válidos: 1m, 8h, 30d.")
    .customSanitizer(ms)
    .custom(value => value >= ms("1m"))
    .withMessage("Minimum expire time should be '1 minuto'.")
    .customSanitizer(value => addMilliseconds(new Date(), value).toISOString()),
  body("domain")
    .optional({ nullable: true, checkFalsy: true })
    .custom(checkUser)
    .withMessage("Apenas usuários podem usar este campo.")
    .isString()
    .withMessage("Domínio deve ser.")
    .customSanitizer(value => value.toLowerCase())
    .customSanitizer(value => removeWww(URL.parse(value).hostname || value))
    .custom(async (address, { req }) => {
      if (address === env.DEFAULT_DOMAIN) {
        req.body.domain = null;
        return;
      }

      const domain = await query.domain.find({
        address,
        user_id: req.user.id
      });
      req.body.domain = domain || null;

      if (!domain) return Promise.reject();
    })
    .withMessage("Você não pode usar este domínio.")
];

export const editLink = [
  body("target")
    .optional({ checkFalsy: true, nullable: true })
    .isString()
    .trim()
    .isLength({ min: 1, max: 2040 })
    .withMessage("O comprimento máximo do URL é 2.040.")
    .customSanitizer(addProtocol)
    .custom(
      value =>
        urlRegex({ exact: true, strict: false }).test(value) ||
        /^(?!https?)(\w+):\/\//.test(value)
    )
    .withMessage("URL não válida.")
    .custom(value => removeWww(URL.parse(value).host) !== env.DEFAULT_DOMAIN)
    .withMessage(`${env.DEFAULT_DOMAIN} URLs não são permitidos.`),
  body("address")
    .optional({ checkFalsy: true, nullable: true })
    .isString()
    .trim()
    .isLength({ min: 1, max: 64 })
    .withMessage("O comprimento do URL personalizado deve estar entre 1 e 64.")
    .custom(value => /^[a-zA-Z0-9-_]+$/g.test(value))
    .withMessage("URL personalizado não é válido")
    .custom(value => !preservedUrls.some(url => url.toLowerCase() === value))
    .withMessage("Você não pode usar este URL personalizado."),
  body("expire_in")
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .trim()
    .custom(value => {
      try {
        return !!ms(value);
      } catch {
        return false;
      }
    })
    .withMessage("O formato de expiração é inválido. Exemplos válidos: 1m, 8h, 42d.")
    .customSanitizer(ms)
    .custom(value => value >= ms("1m"))
    .withMessage("Minimum expire time should be '1 minuto'.")
    .customSanitizer(value => addMilliseconds(new Date(), value).toISOString()),
  body("description")
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .trim()
    .isLength({ min: 0, max: 2040 })
    .withMessage("O comprimento da descrição deve estar entre 0 e 2040."),
  param("id", "ID é inválido.")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 36, max: 36 })
];

export const redirectProtected = [
  body("password", "Password is invalid.")
    .exists({ checkFalsy: true, checkNull: true })
    .isString()
    .isLength({ min: 3, max: 64 })
    .withMessage("O comprimento da senha deve estar entre 3 e 64."),
  param("id", "ID é inválido.")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 36, max: 36 })
];

export const addDomain = [
  body("address", "Domínio não é válido")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 3, max: 64 })
    .withMessage("O comprimento do domínio deve estar entre 3 e 64.")
    .trim()
    .customSanitizer(value => {
      const parsed = URL.parse(value);
      return removeWww(parsed.hostname || parsed.href);
    })
    .custom(value => urlRegex({ exact: true, strict: false }).test(value))
    .custom(value => value !== env.DEFAULT_DOMAIN)
    .withMessage("Você não pode usar o domínio padrão.")
    .custom(async value => {
      const domain = await query.domain.find({ address: value });
      if (domain?.user_id || domain?.banned) return Promise.reject();
    })
    .withMessage("Você não pode adicionar este domínio."),
  body("homepage")
    .optional({ checkFalsy: true, nullable: true })
    .customSanitizer(addProtocol)
    .custom(value => urlRegex({ exact: true, strict: false }).test(value))
    .withMessage("A página inicial não é válida.")
];

export const removeDomain = [
  param("id", "ID é inválido.")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isLength({ min: 36, max: 36 })
];

export const deleteLink = [
  param("id", "ID é invalido.")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isLength({ min: 36, max: 36 })
];

export const reportLink = [
  body("link", "Nenhum link foi fornecido.")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .customSanitizer(addProtocol)
    .custom(
      value => removeWww(URL.parse(value).hostname) === env.DEFAULT_DOMAIN
    )
    .withMessage(`Você só pode denunciar um ${env.DEFAULT_DOMAIN} link.`)
];

export const banLink = [
  param("id", "ID é inválido.")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isLength({ min: 36, max: 36 }),
  body("host", '"host" deveria ser um booleano.')
    .optional({
      nullable: true
    })
    .isBoolean(),
  body("user", '"user" deveria ser um booleano.')
    .optional({
      nullable: true
    })
    .isBoolean(),
  body("userlinks", '"userlinks" deveria ser um booleano.')
    .optional({
      nullable: true
    })
    .isBoolean(),
  body("domain", '"domain" deveria ser um booleano.')
    .optional({
      nullable: true
    })
    .isBoolean()
];

export const getStats = [
  param("id", "ID é invalido.")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isLength({ min: 36, max: 36 })
];

export const signup = [
  body("password", "Senha não é válida.")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("O comprimento da senha deve ser entre 8 e 64."),
  body("email", "E-mail não é válido.")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isEmail()
    .isLength({ min: 0, max: 255 })
    .withMessage("O comprimento do e-mail deve ser de no máximo 255.")
    .custom(async (value, { req }) => {
      const user = await query.user.find({ email: value });

      if (user) {
        req.user = user;
      }

      if (user?.verified) return Promise.reject();
    })
    .withMessage("Você não pode usar este endereço de e-mail.")
];

export const login = [
  body("password", "Senha não é válida.")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("O comprimento da senha deve ser entre 8 e 64."),
  body("email", "E-mail não é válido.")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isEmail()
    .isLength({ min: 0, max: 255 })
    .withMessage("O comprimento do e-mail deve ser de no máximo 255.")
];

export const changePassword = [
  body("password", "Senha não é válida.")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("O comprimento da senha deve ser entre 8 e 64.")
];

export const resetPasswordRequest = [
  body("email", "E-mail não é válido.")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isEmail()
    .isLength({ min: 0, max: 255 })
    .withMessage("O comprimento do e-mail deve ser de no máximo 255."),
  body("password", "Senha não é válida.")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("O comprimento da senha deve ser entre 8 e 64.")
];

export const resetEmailRequest = [
  body("email", "E-mail não é válido.")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isEmail()
    .isLength({ min: 0, max: 255 })
    .withMessage("O comprimento do e-mail deve ser de no máximo 255.")
];

export const deleteUser = [
  body("password", "Senha não é válida.")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .custom(async (password, { req }) => {
      const isMatch = await bcrypt.compare(password, req.user.password);
      if (!isMatch) return Promise.reject();
    })
];

export const cooldown = (user: User) => {
  if (!env.GOOGLE_SAFE_BROWSING_KEY || !user || !user.cooldowns) return;

  // If has active cooldown then throw error
  const hasCooldownNow = user.cooldowns.some(cooldown =>
    isAfter(subHours(new Date(), 12), new Date(cooldown))
  );

  if (hasCooldownNow) {
    throw new CustomError("Congelado por causa de um URL de malware. Espere 12h");
  }
};

export const malware = async (user: User, target: string) => {
  if (!env.GOOGLE_SAFE_BROWSING_KEY) return;

  const isMalware = await axios.post(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${env.GOOGLE_SAFE_BROWSING_KEY}`,
    {
      client: {
        clientId: env.DEFAULT_DOMAIN.toLowerCase().replace(".", ""),
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: [
          "THREAT_TYPE_UNSPECIFIED",
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes: ["ANY_PLATFORM", "PLATFORM_TYPE_UNSPECIFIED"],
        threatEntryTypes: [
          "EXECUTABLE",
          "URL",
          "THREAT_ENTRY_TYPE_UNSPECIFIED"
        ],
        threatEntries: [{ url: target }]
      }
    }
  );
  if (!isMalware.data || !isMalware.data.matches) return;

  if (user) {
    const [updatedUser] = await query.user.update(
      { id: user.id },
      {
        cooldowns: knex.raw("array_append(cooldowns, ?)", [
          new Date().toISOString()
        ]) as any
      }
    );

    // Ban if too many cooldowns
    if (updatedUser.cooldowns.length > 2) {
      await query.user.update({ id: user.id }, { banned: true });
      throw new CustomError("Muitos pedidos de malware. Agora você está banido.");
    }
  }

  throw new CustomError(
    user ? "Malware detectado! Congelado por 12h." : "Malware detectado!"
  );
};

export const linksCount = async (user?: User) => {
  if (!user) return;

  const count = await query.link.total({
    user_id: user.id,
    created_at: [">", subDays(new Date(), 1).toISOString()]
  });

  if (count > env.USER_LIMIT_PER_DAY) {
    throw new CustomError(
      `Você atingiu seu limite diário (${env.USER_LIMIT_PER_DAY}). Por favor espere 24h.`
    );
  }
};

export const bannedDomain = async (domain: string) => {
  const isBanned = await query.domain.find({
    address: domain,
    banned: true
  });

  if (isBanned) {
    throw new CustomError("URL está contendo malware/scam.", 400);
  }
};

export const bannedHost = async (domain: string) => {
  let isBanned;

  try {
    const dnsRes = await dnsLookup(domain);

    if (!dnsRes || !dnsRes.address) return;

    isBanned = await query.host.find({
      address: dnsRes.address,
      banned: true
    });
  } catch (error) {
    isBanned = null;
  }

  if (isBanned) {
    throw new CustomError("URL está contendo malware/scam.", 400);
  }
};
