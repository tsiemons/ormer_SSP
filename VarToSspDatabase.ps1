Function import-varssp{
    [cmdletbinding()]
    param ( 
            [parameter(
                Mandatory=$False,
                Position=1
                ) ][string[]]$LogFile
        )
    #region Begin
    $ServerInstance = 'tcp:10.1.1.50,1433'
    $Database = 'ORME-SSP-01'
    $UserName = 'svc_ssp_RW'
    $Password = 'lkjq4365lqkj3456lqkj4tlqkj4tblkj'
    $QueryTimeout = 600
    $ConnectionTimeout = 15
    
    $dir = get-childitem c:\kworking "S*.csv"
    Foreach ($file in $dir)
    {
        $LogFilePath = $file.fullname
    #endregion Begin

        $Connectionstring = "Server = $ServerInstance; 
                            Database = $Database; 
                            User ID= $username; 
                            Password= $Password; 
                            Integrated Security= False;
                            Encrypt= True;
                            Trusted_Connection= False;
                            TrustServerCertificate=True;" 
        try {
            ##########################
            # Open database
            ##########################

            $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
            $SqlConnection.ConnectionString = $Connectionstring
            $Sqlconnection.Open()

            } # End try

        catch {

                Write-Error $_

            } # End Catch

        $LogFile = import-csv -Path $LogFilePath -delim ";"
        foreach ($var in $LogFile) { 
        
            $Query = "insert into [P-1.0-Logs]
                    (logID,sspUid,action,result,companyID,parameters,youweID,last_changed) 
                    values ('$($var.logid)',
                    '$($var.sspuid)',
                    '$($var.action)',
                    '$($var.result)',
                    '$($var.companyid)',
                    '$($var.parameters)',
                    '$($var.youweid)',
                    '$($var.last_changed)'
                    )"
    $query
            try {

                ################################
                # Write Record to database 
                ################################

                $Cmd = New-Object system.Data.SqlClient.SqlCommand($Query,$SqlConnection) 
                $Cmd.CommandTimeout=$QueryTimeout 
                $ds = New-Object system.Data.DataSet 
                $da = New-Object system.Data.SqlClient.SqlDataAdapter($Cmd) 
                [void]$da.fill($ds)
                $ds.Tables[0]

                Write-verbose "Record added"

                } # End Try
            Catch {
                    Write-Error $_
                } #End Catch
    
        } # end foreach


        ######################
        #   Close Database
        ######################

        try {

            # database Interaction

            $Sqlconnection.Close()

            #End :database Interaction

            } #End Try

        Catch {

        Write-Error $_
        }
        rename-item $file "arch_ssp$(get-date -format dd-MM-yy_hh-mm).csv"
    }     
}
Do {
    import-varssp
    sleep 10
}
Until (1 -gt 10)