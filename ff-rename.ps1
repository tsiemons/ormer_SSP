

$dir = "C:\Users\tsiemons\OneDrive\Powershell\SSP\Naam conventie"
cd $dir
$files = gci $dir
foreach ($file in $files){
    $newnamearr = ($file.name -split ".")
    $newname = "$($newnamearr[1])$($newnamearr[0]).$($newnamearr[2])"
    $newname
}
