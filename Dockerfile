FROM node:22-bookworm-slim
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN mkdir -p /app/data
ENV NODE_ENV=production
ENV PORT=8787
EXPOSE 8787
CMD ["pnpm", "start:node"]
