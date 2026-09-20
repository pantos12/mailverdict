# MailVerdict container image (Azure Container Apps / any Docker host).
FROM node:22-alpine AS base
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
# tsx is a devDependency and is used to run TypeScript directly at runtime.
RUN npm ci --include=dev --ignore-scripts && npm cache clean --force
COPY tsconfig.json ./
COPY src ./src
COPY api ./api
COPY public ./public
EXPOSE 8080
ENV PORT=8080
USER node
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8080/health || exit 1
CMD ["npx", "tsx", "src/server.ts"]
