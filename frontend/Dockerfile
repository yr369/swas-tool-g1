# Frontend Dockerfile - multi-stage build.
#
# Stage 1 compiles the React app into static files (HTML/JS/CSS).
# Stage 2 serves those static files with nginx - a much smaller, simpler
# final image than shipping Node.js itself, which isn't needed at runtime.

FROM node:20-alpine AS build

WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
