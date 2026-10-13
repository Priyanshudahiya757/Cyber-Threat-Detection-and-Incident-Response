FROM node:22-slim

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5173

# Dev-mode container (matches the rest of this project's docker-compose
# setup, which favors live-reload over a production nginx/static build).
# A production image would instead run `npm run build` and serve dist/
# via nginx — worth revisiting once the frontend is feature-complete.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
