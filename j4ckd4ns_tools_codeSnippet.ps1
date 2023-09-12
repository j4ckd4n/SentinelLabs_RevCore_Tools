Set-ExecutionPolicy Unrestricted;
iex ((New-Object System.Net.WebClient).DownloadString('http://boxstarter.org/bootstrapper.ps1'));
get-boxstarter -Force;
Install-BoxstarterPackage -PackageName 'https://raw.githubusercontent.com/j4ckd4n/j4ckd4ns_mal_tools/master/j4ckd4ns_mal_tools.ps1';
