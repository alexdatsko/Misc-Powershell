# Get list of versions for all files
param ([string] $files)

if (!($files)) {
  $files=@('file1','file2')
}
Foreach ($file in $files) {
  $file
  (Get-Command $file).FileVersionInfo.FileVersion
}