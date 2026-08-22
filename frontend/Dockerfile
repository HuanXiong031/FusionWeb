FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.28-alpine
RUN apk add --no-cache openssl apache2-utils
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist/ /usr/share/nginx/html/
COPY docker-entrypoint.sh /docker-entrypoint.d/20-fusionweb.sh
RUN chmod +x /docker-entrypoint.d/20-fusionweb.sh
EXPOSE 80 443
