# ECDAT Monorepo

Welcome to the Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) monorepo.

## Restarting the Application

If you need to restart the application (for example, to apply new changes), follow these detailed instructions for both the frontend and backend.

### 1. Restarting the Backend

The backend runs on Python/FastAPI using Uvicorn (usually on port 8000).

**To restart the backend:**
1. Locate the terminal window running the backend process and press `Ctrl + C` to stop the server.
2. Alternatively, if it is running in the background, you can kill the process using port 8000:
   - On Windows (PowerShell):
     ```powershell
     $pid = (Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue).OwningProcess
     if ($pid) { Stop-Process -Id $pid -Force }
     ```
3. Start the backend again by running the batch script from the monorepo root:
   ```cmd
   .\start_backend.bat
   ```

### 2. Restarting the Frontend

The frontend is a React application powered by Vite (usually on port 5173).

**To restart the frontend:**
1. Locate the terminal window running the frontend process and press `Ctrl + C` to stop Vite.
2. Alternatively, if it is running in the background, you can kill the process using port 5173:
   - On Windows (PowerShell):
     ```powershell
     $pid = (Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue).OwningProcess
     if ($pid) { Stop-Process -Id $pid -Force }
     ```
3. Open a terminal in the `frontend` directory and start the development server again:
   ```cmd
   cd frontend
   npm run dev
   ```

## Development

- **Frontend**: React, Vite, TailwindCSS
- **Backend**: Python, FastAPI, Uvicorn
