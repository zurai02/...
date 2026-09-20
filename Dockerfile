FROM node:20-alpine

ENV NODE_ENV=production

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev

COPY public ./public
COPY server ./server
COPY scripts ./scripts

RUN mkdir -p /app/data \
    && node server/server.js --validate-luau

USER node

EXPOSE 3000

CMD ["node", "server/server.js"]
