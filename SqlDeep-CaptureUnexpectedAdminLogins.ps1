$myDurationMinute = -5
$myExceptedLogins = ("SQLDEEP\SQL_Service,SQLDEEP\SQL_Agent").ToUpper().Split(",")
$myMaster = "DB-MN-DLV01.SQLDEEP.COM\NODE,49149"
$myStartTime = (Get-Date).AddMinutes($myDurationMinute);

#-----Functions
Function Get-CurrentInstanceOfAgent {  #Retrive Current Instance Name if this script execute from SQL Agent
    [string]$myAnswer=""
    try {
        $myInstanceName='$(ESCAPE_SQUOTE(INST))'
        $myMachineName='$(ESCAPE_SQUOTE(MACH))'
        $myRegFilter='HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*.'+$myInstanceName+'\MSSQLServer\SuperSocketNetLib\Tcp\IPAll'
        $myPort=(Get-ItemProperty -Path $myRegFilter).TcpPort.Split(',')[0]
        $myDomainName=(Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain
        $myConnection=$myMachineName
        if ($myDomainName) {$myConnection += '.' + $myDomainName}
        if ($myInstanceName -ne "MSSQLSERVER") {$myConnection += '\' + $myInstanceName}
        if ($myPort) {$myConnection += ',' + $myPort}
        $myAnswer=$myConnection
    }
    catch
    {
        Write-Log -Type WRN -Content ($_.ToString()).ToString()
    }
    return $myAnswer
}

$myInstance = (Get-CurrentInstanceOfAgent).ToUpper()

#-----Retrive Successful Logins
Write-Host "Retrive Successful Logins"
Remove-Variable myFilteredLogs -ErrorAction SilentlyContinue
$myNonAdminLoginsQuery = "
    --Get Windows Group Logins/members
    SET NOCOUNT ON;
    DECLARE @myGroupName sysname
    CREATE TABLE #myDomainGroupMembers ([account_name] sysname, [type] Char(8), [privilege] Char(9), [mapped login name] sysname, [permission path] sysname)
    DECLARE myDomainGroups CURSOR FOR 
    SELECT
	    UPPER([myLogins].[name]) AS GroupName
    FROM
	    master.sys.server_principals AS myLogins
    WHERE
	    IS_SRVROLEMEMBER('sysadmin',[myLogins].[name]) = 0
	    AND [myLogins].[type] IN ('G')

    OPEN myDomainGroups
    FETCH NEXT FROM myDomainGroups 
    INTO @myGroupName
    WHILE @@FETCH_STATUS = 0
    BEGIN
	    INSERT INTO #myDomainGroupMembers EXEC master..xp_logininfo @acctname =@myGroupName, @option = 'members'
        FETCH NEXT FROM myDomainGroups 
        INTO @myGroupName
    END 
    CLOSE myDomainGroups;
    DEALLOCATE myDomainGroups;

    --Get Regular Logins
    SELECT
	    UPPER(CAST(REPLACE(@@SERVERNAME,'\','.SQLDEEP.COM\') + CASE WHEN CHARINDEX('\',@@SERVERNAME)=0 THEN '.SQLDEEP.COM' ELSE '' END + ',49149' AS NVARCHAR(255))) AS InstanceName,
	    UPPER([myLogins].[name]) AS LoginName
    FROM
	    master.sys.server_principals AS myLogins
    WHERE
	    IS_SRVROLEMEMBER('sysadmin',[myLogins].[name]) = 0
	    AND [myLogins].[type] NOT IN ('C','R','G')
    UNION
    --Get Group Logins
    SELECT
	    UPPER(CAST(REPLACE(@@SERVERNAME,'\','.SQLDEEP.COM\') + CASE WHEN CHARINDEX('\',@@SERVERNAME)=0 THEN '.SQLDEEP.COM' ELSE '' END + ',49149' AS NVARCHAR(255))) AS InstanceName,
	    UPPER([myGroupMembers].[account_name]) AS LoginName
    FROM
	    master.sys.server_principals AS myGroups
	    INNER JOIN #myDomainGroupMembers AS myGroupMembers ON UPPER([myGroups].[name])=UPPER([myGroupMembers].[permission path])
    WHERE
	    IS_SRVROLEMEMBER('sysadmin',[myGroups].[name]) = 0
	    AND [myGroups].[type] IN ('G')
	    AND ISNULL([myGroupMembers].[privilege],'') <> 'admin'
    DROP TABLE #myDomainGroupMembers 
"
$myNonAdmins = Invoke-Sqlcmd -ServerInstance $myInstance -Query $myNonAdminLoginsQuery -OutputSqlErrors $true -QueryTimeout 0 -OutputAs DataRows -ErrorAction Stop
$myFilteredLogs = Get-WinEvent -FilterHashtable @{
                                                    LogName='Application'
                                                    ProviderName='MSSQL$NODE'
                                                    StartTime=$myStartTime
                                                    Id=33205} `
    | Where-Object {$_.Message -ilike "*action_id:LGIS*server_principal_name:*server_instance_name:*host_name:*" } `
    | Where-Object {$_.Message -match "(\nserver_principal_name:(?<login>.+))+(.|\n)*(\nserver_instance_name:(?<instance>.+))+(.|\n)*(\nhost_name:(?<client>.+))" } `
    | Where-Object {$matches['login'].ToUpper() -notin $myExceptedLogins } `
    | Where-Object {$matches['login'].ToUpper() -notin $myNonAdmins.LoginName } `
    | ForEach {New-Object psobject `
        -prop @{ Time=$_.TimeCreated; Login=$matches['login'].ToUpper(); Instance=$matches['instance'].ToUpper(); Client=$matches['client'].ToUpper() } 
        } 

#-----Insert Event Logs
IF ($myFilteredLogs.Count -gt 0) {
    Write-Host "Insert Event Logs"
    ForEach ($myEvent in $myFilteredLogs) {
        $myInserEventCommand="
        USE [Tempdb];
        DECLARE @BatchInsertTime DateTime;
        DECLARE @myTime DateTime;
        DECLARE @myLogin sysname;
        DECLARE @myInstance nvarchar(256);
        DECLARE @myClient nvarchar(256);

        SET @BatchInsertTime=CAST(N'"+$myStartTime.ToString()+"' AS DATETIME);
        SET @myTime=CAST(N'"+$myEvent.Time+"' AS DATETIME);
        SET @myLogin=N'"+$myEvent.Login+"';
        SET @myInstance=N'"+$myEvent.Instance+"';
        SET @myClient=N'"+$myEvent.Client+"';

        IF OBJECT_ID('LogonRecords') IS NULL
        BEGIN
	        CREATE TABLE dbo.LogonRecords ([Id] bigint identity Primary Key, [BatchInsertTime] DateTime NOT NULL, [Time] DateTime NOT NULL, [Login] nvarchar(128) NOT NULL, [Instance] nvarchar(256) NOT NULL, [Client] nvarchar(256));
	        CREATE INDEX NCIX_dbo_LogonRecords_Instance ON dbo.LogonRecords ([Instance],[BatchInsertTime]) WITH (DATA_COMPRESSION=PAGE,FILLFACTOR=85);
	        CREATE INDEX NCIX_dbo_LogonRecords_LoginTime ON dbo.LogonRecords ([Login],[Time]) WITH (DATA_COMPRESSION=PAGE,FILLFACTOR=85);
        END

        INSERT INTO dbo.LogonRecords ([BatchInsertTime],[Time],[Login],[Instance],[Client]) VALUES (@BatchInsertTime,@myTime,@myLogin,@myInstance,@myClient);
        "
        Invoke-Sqlcmd -ServerInstance $myMaster -Database "Tempdb" -Query $myInserEventCommand -OutputSqlErrors $true -QueryTimeout 0 -ErrorAction Stop
    }
} ELSE {
    Write-Host "Insert Event Logs: there is nothing"
}

#-----Clean Event Logs
IF ($myFilteredLogs.Count -gt 0) {
    Write-Host "Validate Event Logs"
    $myValidateEventCommand="
        USE [Tempdb];
        DECLARE @BatchInsertTime DateTime;
        DECLARE @myInstance nvarchar(256);
        SET @BatchInsertTime=CAST(N'"+$myStartTime.ToString()+"' AS DATETIME);
        SET @myInstance=N'"+$myFilteredLogs[0].Instance+"';

        DELETE dbo.LogonRecords WHERE [Instance]=@myInstance AND [BatchInsertTime] < @BatchInsertTime;
        "
    Invoke-Sqlcmd -ServerInstance $myMaster -Database "Tempdb" -Query $myValidateEventCommand -OutputSqlErrors $true -QueryTimeout 0 -ErrorAction Stop
} ELSE {
    Write-Host "Validate Event Logs: There is nothing"
}

#-----Analyze Event Logs
IF ($myFilteredLogs.Count -gt 0) {
    Write-Host "Analyze Event Logs"
    $myAnalyzeEventCommand="
        USE [Tempdb];
        DECLARE @myInstance nvarchar(256)
        DECLARE @myCurrent DATETIME;
        DECLARE @myDummeyDate DATETIME;
        DECLARE @myKnownList TABLE ([Login] nvarchar(128), [PersonelID] bigint, [Client] nvarchar(256))
        DECLARE @myLogonStat TABLE ([Login] nvarchar(128), [Client] nvarchar(256), [StartDateTime] DateTime, [FinishDateTime] DateTime, [StartTime] Time(0), [FinishTime] Time(0), [StartDateJalali] nvarchar(10), [FinishDateJalali] nvarchar(10), [PersonelID] bigint, [LoginAttempts] bigint);

        SET @myInstance=N'"+$myFilteredLogs[0].Instance+"';
        SET @myCurrent=GETDATE();
        SET @myDummeyDate=CAST(@myCurrent AS DATE)
        IF OBJECT_ID('LogonRecords') IS NOT NULL
        BEGIN											--List your expected sql admin domain logins, personnel id and allowed clients for sql logins in UPPER CASE !!!
            INSERT INTO @myKnownList ([Login],[PersonelID],[Client]) VALUES
            (N''SQLDEEP\AMINMAZIDI'',10001,N''CLIENTAMIN%''),
            (N''SQLDEEP\EHSANHOSSEINPOUR'',10002,N''CLIENTEHSAN''),
            (N''SQLDEEP\SIAVASHGOLCHOOBIAN'',10003,N''%CLIENTSIA%'')

            INSERT INTO @myLogonStat ([Login],[Client],[StartDateTime],[FinishDateTime],[StartTime],[FinishTime],[StartDateJalali],[FinishDateJalali],[LoginAttempts],[PersonelID])
            SELECT
	            [myLogs].[Login],
	            [myLogs].[Client],
	            [myLogs].[StartTime],
	            [myLogs].[FinishTime],
	            CAST([myLogs].[StartTime] AS Time(0)),
	            CAST([myLogs].[FinishTime] AS Time(0)),
	            [SqlDeep].[dbo].[dbafn_miladi2shamsi]([myLogs].[StartTime],'/'),
	            [SqlDeep].[dbo].[dbafn_miladi2shamsi]([myLogs].[FinishTime],'/'),
	            [myLogs].[LoginAttempts],
	            [myKnownList].[PersonelID]
            FROM
	            (
		            SELECT 
			            [myRawLog].[Login],
			            [myRawLog].[Client],
			            MIN([myRawLog].[Time]) AS StartTime,
			            MAX([myRawLog].[Time]) AS FinishTime,
			            Count(1) AS LoginAttempts
		            FROM 
			            [dbo].[LogonRecords] AS myRawLog WITH (READPAST)
		            WHERE
			            [myRawLog].[Instance]=@myInstance
		            GROUP BY
			            [myRawLog].[Login],
			            [myRawLog].[Client]
	            ) AS myLogs
	            LEFT OUTER JOIN @myKnownList AS myKnownList ON [myLogs].[Login]=[myKnownList].[Login] AND [myLogs].[Client] LIKE [myKnownList].[Client]


            INSERT INTO [EventLog].[dbo].[Events] ([EventSource],[Module],[EventTimeStamp],[Serverity],[Description],[IsSMS])
            SELECT 
	            @myInstance,
	            N'AdminLogins',
	            [myLogonStat].[StartDateTime],
	            N'WRN',
	            N'Unexpected Login as sysadmin from '+ [myLogonStat].[Client] +N' client with ' + [myLogonStat].[Login] + N' login between ' + CAST([myLogonStat].[StartTime] AS nvarchar(10)) + N' and ' + CAST([myLogonStat].[FinishTime] AS nvarchar(10)) + N' for ' + CAST([myLogonStat].[LoginAttempts] AS nvarchar(10)) + N' times.',
	            1
            FROM 
	            @myLogonStat AS myLogonStat
	            OUTER APPLY (
		            SELECT
			            [myKasraStat].[Date],
			            [myKasraStat].[InTime],
			            CASE WHEN [myKasraStat].[InTime]=[myKasraStat].[OutTime] THEN CAST(@myCurrent AS TIME(0)) ELSE [myKasraStat].[OutTime] END AS OutTime
		            FROM
			            (
			            SELECT
				            [Date],
				            MIN(CAST(DATEADD(MINUTE,[Time],@myDummeyDate) AS TIME(0))) AS [InTime],
				            MAX(CAST(DATEADD(MINUTE,[Time],@myDummeyDate) AS TIME(0))) AS [OutTime]
			            FROM 
				            [LSNRKASRA].[framework].[Att].[Attendance]
			            WHERE
				            PersonelID=[myLogonStat].[PersonelID] AND [DATE] BETWEEN [myLogonStat].[StartDateJalali] COLLATE Arabic_CI_AS AND [myLogonStat].[FinishDateJalali] COLLATE Arabic_CI_AS
			            GROUP BY
				            [Date]
			            ) AS myKasraStat
	            ) AS myKasraSummery
            WHERE
	            [myLogonStat].[PersonelID] IS NULL			--From unknown Admins or known admins from unknown clients
	            OR											--Known Admins
	            (
		            [myLogonStat].[PersonelID] IS NOT NULL
		            AND 
			            (
			            NOT ([myLogonStat].[StartTime] BETWEEN [myKasraSummery].[InTime] AND [myKasraSummery].[OutTime])
			            OR
			            NOT ([myLogonStat].[FinishTime] BETWEEN [myKasraSummery].[InTime] AND [myKasraSummery].[OutTime])
			            )
	            )
         END
"
    Invoke-Sqlcmd -ServerInstance $myMaster -Database "Tempdb" -Query $myAnalyzeEventCommand -OutputSqlErrors $true -QueryTimeout 0 -ErrorAction Stop
} ELSE {
    Write-Host "Analyze Event Logs: There is nothing"
}