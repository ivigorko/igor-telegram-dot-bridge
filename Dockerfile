FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --chown=node:node package.json callback-server.mjs security.mjs ./
COPY --chown=node:node lib/crypto.mjs ./lib/crypto.mjs
USER node
EXPOSE 10000
CMD ["node", "callback-server.mjs"]
