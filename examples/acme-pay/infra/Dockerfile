FROM node:22-slim
WORKDIR /app
COPY . .
COPY keys/ /app/keys/
ENV TREASURY_PRIVATE_KEY=set-at-build
CMD ["node", "server/index.js"]
