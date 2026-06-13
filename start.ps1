# Start Backend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; npm start" -WindowStyle Normal

# Wait a moment for backend to start
Start-Sleep -Seconds 2

# Start Frontend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\frontend'; npm run dev" -WindowStyle Normal

Write-Host ""
Write-Host "==========================================="
Write-Host "  ShieldScan is starting up!"
Write-Host "==========================================="
Write-Host "  Frontend: http://localhost:5173"
Write-Host "  Backend:  http://localhost:3001"
Write-Host "==========================================="
Write-Host ""
Write-Host "Both servers are opening in new windows."
Write-Host "Open http://localhost:5173 in your browser."
