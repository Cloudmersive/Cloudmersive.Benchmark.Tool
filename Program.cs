using Cloudmersive.APIClient.NETCore.VirusScan.Api;
using Cloudmersive.APIClient.NETCore.VirusScan.Client;
using Cloudmersive.APIClient.NETCore.VirusScan.Model;
using System.Diagnostics;

Console.WriteLine("Starting...");

string Path = "C:\\inputfiles";

var files = Directory.EnumerateFiles(Path);

foreach (var file in files)
{
    var apiInstance = new ScanApi();


    apiInstance.Configuration = new Configuration();
    apiInstance.Configuration.AddApiKey("Apikey", "YOUR-API-KEY");

    var inputFile = new System.IO.FileStream(file, System.IO.FileMode.Open); // System.IO.Stream | Input file to perform the operation on.
    var allowExecutables = false;  // bool? | Set to false to block executable files (program code) from being allowed in the input file.  Default is false (recommended). (optional) 
    var allowInvalidFiles = false;  // bool? | Set to false to block invalid files, such as a PDF file that is not really a valid PDF file, or a Word Document that is not a valid Word Document.  Default is false (recommended). (optional) 
    var allowScripts = false;  // bool? | Set to false to block script files, such as a PHP files, Python scripts, and other malicious content or security threats that can be embedded in the file.  Set to true to allow these file types.  Default is false (recommended). (optional) 
    var allowPasswordProtectedFiles = false;  // bool? | Set to false to block password protected and encrypted files, such as encrypted zip and rar files, and other files that seek to circumvent scanning through passwords.  Set to true to allow these file types.  Default is false (recommended). (optional) 
    var allowMacros = false;  // bool? | Set to false to block macros and other threats embedded in document files, such as Word, Excel and PowerPoint embedded Macros, and other files that contain embedded content threats.  Set to true to allow these file types.  Default is false (recommended). (optional) 
    var allowXmlExternalEntities = false;  // bool? | Set to false to block XML External Entities and other threats embedded in XML files, and other files that contain embedded content threats.  Set to true to allow these file types.  Default is false (recommended). (optional) 
    var allowInsecureDeserialization = false;  // bool? | Set to false to block Insecure Deserialization and other threats embedded in JSON and other object serialization files, and other files that contain embedded content threats.  Set to true to allow these file types.  Default is false (recommended). (optional) 
    var allowHtml = false;  // bool? | Set to false to block HTML input in the top level file; HTML can contain XSS, scripts, local file accesses and other threats.  Set to true to allow these file types.  Default is false (recommended) [for API keys created prior to the release of this feature default is true for backward compatability]. (optional) 
    var restrictFileTypes = "";  // string | Specify a restricted set of file formats to allow as clean as a comma-separated list of file formats, such as .pdf,.docx,.png would allow only PDF, PNG and Word document files.  All files must pass content verification against this list of file formats, if they do not, then the result will be returned as CleanResult=false.  Set restrictFileTypes parameter to null or empty string to disable; default is disabled. (optional) 

    var startTime = DateTime.Now;

    // Advanced Scan a file for viruses
    VirusScanAdvancedResult result = apiInstance.ScanFileAdvanced(inputFile, allowExecutables, allowInvalidFiles, allowScripts, allowPasswordProtectedFiles, allowMacros, allowXmlExternalEntities, allowInsecureDeserialization, allowHtml, restrictFileTypes);
    

    var endTime = DateTime.Now;
    var duration = endTime.Subtract(startTime);

    string newLine = file +", " + duration.TotalSeconds.ToString();

    Console.WriteLine(newLine);

    File.AppendAllText(Path + "\\results.csv", newLine + "\n");
}

Console.WriteLine("Done.");