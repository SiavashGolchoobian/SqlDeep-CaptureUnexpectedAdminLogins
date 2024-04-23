This project depends on creating SQL Server Audit (like SqlDeep_TrackLogins.sql) and save the audit result in Windows Event Log.
Then uou need to create a job (SqlDeep_CaptureAdminLogins.sql) to capture and analyze Unknown SQL Admins or allowed SQL Admins that login from unknown client or login on unexpected time (in this script i check admins with their Kasra App times)
