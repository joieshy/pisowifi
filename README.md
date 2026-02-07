# PisoWiFi Project

A simple PisoWiFi management system built with Node.js, Express, and SQLite3.

## Features
- Admin Dashboard
- User Session Management
- Sales Reporting
- Voucher Generation
- System Diagnostics (Ping, Speed Test)
- Security (MAC Filtering, Website Blocking)

## Prerequisites
- [Node.js](https://nodejs.org/) (v14 or higher)
- npm (comes with Node.js)

## Installation

1. Clone the repository:
   ```bash
   git clone <your-repository-url>
   cd PISOWIFI
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Update the values in `.env` as needed
   ```bash
   cp .env.example .env
   ```

4. Start the server:
   ```bash
   npm start
   ```
   The server will be running at `http://localhost:3000` (or the port specified in your `.env`).

## Project Structure
- `server.js`: Main entry point of the application.
- `public/`: Frontend files (HTML, CSS, JS).
- `uploads/`: User-uploaded files (wallpapers, logos, etc.).
- `media/`: Default system media files.
- `pisowifi.db`: SQLite database (auto-generated on first run).

## Security Note
- The `.env` file and `pisowifi.db` are ignored by Git to protect sensitive information and local data.
- Make sure to change the `SESSION_SECRET` in your `.env` file for production use.

## License
ISC
