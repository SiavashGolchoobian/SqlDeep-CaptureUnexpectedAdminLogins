USE [master]
GO

/****** Object:  Audit [SqlDeep_TrackLogins]    Script Date: 4/23/2024 10:02:07 AM ******/
CREATE SERVER AUDIT [SqlDeep_TrackLogins]
TO APPLICATION_LOG WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE, AUDIT_GUID = '7efd8766-ecab-4d1c-837a-9b34aecb00c8')
ALTER SERVER AUDIT [SqlDeep_TrackLogins] WITH (STATE = ON)
GO

