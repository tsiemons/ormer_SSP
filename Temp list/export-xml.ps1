$companies = @()
$csv = import-csv "C:\Users\tsiemons\OneDrive\Powershell\SSP\Temp list\ExportManageAgentList.csv"
foreach ($item in $csv){
    $id = $item.'machine id'
    #$id
    $companyarr = $id.split(".")
    $company = "$($companyarr[2]).$($companyarr[1])"
    
    $companies += $company
}
$companies |select -unique
Foreach ($xml in $companies){
    $xmlfile = "C:\Users\tsiemons\OneDrive\Powershell\SSP\Naam conventie\$($xml).xml"
    copy "C:\Users\tsiemons\OneDrive\Powershell\SSP\Naam conventie\rogplus.srv.xml" $xmlfile
}