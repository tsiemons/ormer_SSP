#[XML]$adsettings=get-content "C:\Users\tsiemons\OneDrive\Powershell\SSP\ad.xml"
#$displayname = $adsettings.customer.nc_displayname




Function Convert-formatstring
{
[cmdletbinding()]
param (
    [parameter(mandatory=$false)]
    [string]$tring
)
    Switch -Regex ($tring)
    {
        "%G\d+"{
            $n=$tring |select-string -pattern "%G\d+" -AllMatches
            $n.matches.value|foreach-object {
            [int]$number = (select-string -input $_ -pattern "\d+").Matches.value
            $givenname = $givenname.substring(0,[int]$number)
            $tring=$tring.replace("$_","$givenname")
            }
        }
        "%G"{$tring=$tring.replace("%G","$givenname")}
        "%S\d+"{
            $n=$tring |select-string -pattern "%S\d+" -AllMatches
            $n.matches.value|foreach-object {
            [int]$number = (select-string -input $_ -pattern "\d+").Matches.value
            $surname = $surname.substring(0,[int]$number)
            $tring=$tring.replace("$_","$surname")
            }
        }
        "%S"{$tring=$tring.replace("%S","$surname")}
        "%I\d+"{
            $n=$tring |select-string -pattern "%I\d+" -AllMatches
            $n.matches.value|foreach-object {
            [int]$number = (select-string -input $_ -pattern "\d+").Matches.value
            $initials = $initials.substring(0,[int]$number)
            $tring=$tring.replace("$_","$initials")
            }
        }
        "%I"{$tring=$tring.replace("%I","$initials")}
    }
    $tring
}
Export-ModuleMember Convert-formatstring
