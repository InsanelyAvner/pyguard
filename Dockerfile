# Step 1: Use an official Node image as the builder
FROM node:18-alpine AS builder

# Step 2: Set working directory
WORKDIR /app

# Step 3: Copy package.json and package-lock.json (or yarn.lock)
COPY package*.json ./

# Step 4: Install dependencies
RUN npm install

# Step 5: Copy the rest of the application code
COPY . .

# Step 6: Build the Next.js app
RUN npm run build

# Step 7: Use a smaller Node image for the production build
FROM node:18-alpine AS runner

WORKDIR /app

# Step 8: Copy the built app and necessary files from the builder
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/public ./public

# Step 9: Set environment variable to production
ENV NODE_ENV=production

# Step 10: Expose the port the app runs on
EXPOSE 3000

# Step 11: Command to run the app
CMD ["npm", "run", "start"]
