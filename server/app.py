from flask import Flask, render_template,  redirect, request, url_for, jsonify
import codecs
import subprocess
from sarif import loader


app = Flask(__name__)
app.secret_key = "S3cr3t_K3y_0f_S3rv3r"

dotnet5 = r"..\SecurityCodeScan.Tool\.NET Core\bin\Release\net5.0\security-scan.exe"
dotnet6 = r"..\SecurityCodeScan.Tool\.NET Core\bin\Release\net6.0\security-scan.exe"
dotnetFrameWork4x = r"..\SecurityCodeScan.Tool\.NET 4.x\bin\Release\net48\security-scan.exe"

VulGroupByRule = {}
VulGroupByLocation = {}
ListRule = []

ListLocation = []

mapRuleIdRuleName = {"SCS0001": "Command Injection",
                     "SCS0002": "SQL Injection",
                     "SCS0003": "XPath Injection",
                     "SCS0007": "XML eXternal Entity Injection (XXE)",
                     "SCS0018": "Path Traversal",
                     "SCS0029": "Cross-Site Scripting (XSS)",
                     "SCS0029_1": "Cross-Site Scripting (XSS)",
                     "SCS0029_2": "Cross-Site Scripting (XSS)",
                     "SCS0026": "LDAP Distinguished Name Injection",
                     "SCS0031": "LDAP Filter Injection",
                     "SCS0004": "Certificate Validation Disabled",
                     "SCS0005": "Weak Random Number Generator",
                     "SCS0006": "Weak hashing function",
                     "SCS0010": "Weak cipher algorithm",
                     "SCS0013": "Potential usage of weak CipherMode mode",
                     "SCS0008": "Cookie Without SSL Flag",
                     "SCS0009": "Cookie Without HttpOnly Flag",
                     "SCS0023": "View State Not Encrypted",
                     "SCS0024": "View State MAC Disabled",
                     "SCS0017": "Request Validation Disabled (Attribute)",
                     "SCS0021": "Request Validation Disabled (Configuration File)",
                     "SCS0030": "Request validation is enabled only for pages (Configuration File)",
                     "SCS0015": "Hardcoded Password",
                     "SCS0034": "Password RequiredLength Not Set",
                     "SCS0032": "Password RequiredLength Too Small",
                     "SCS0033": "Password Complexity",
                     "SCS0011": "Unsafe XSLT setting used",
                     "SCS0012": "Controller method is potentially vulnerable to authorization bypass",
                     "SCS0016": "Cross-Site Request Forgery (CSRF)",
                     "SCS0019": "OutputCache Conflict",
                     "SCS0022": "Event Validation Disabled",
                     "SCS0027": "Open Redirect",
                     "SCS0028": "Insecure Deserialization",
                     "SCS0035": "Server-side request forgery (SSRF)",
                     "SCS0036": "Server-Side Template Injection (SSTI)"

                     }

executePath = {
    "1": dotnet5,
    "2": dotnet6,
    "3": dotnetFrameWork4x,
}
extensionLang = {
    "cs": "csharp",
    "config": "xml",
    "cshtml": "razor",
    "aspx": "html"

}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/info')
def info():
    return render_template('info.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    solutionPath = request.form.get('solutionPath')
    SARIFPath = request.form.get('SARIFPath')
    dotnetversion = request.form.get('dotnetversion')
    path = executePath.get(dotnetversion, dotnet5)
    result = subprocess.run([path, solutionPath, "-x", SARIFPath],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    error = result.stderr.decode("utf-8")
    if result.returncode == 0:
        return redirect(url_for('result', sarifPath=SARIFPath))
    else:
        return render_template("error.html", error = error)


######## Data fetch ############
@app.route('/getVulGroupByRuleData', methods=['GET', 'POST'])
def data_get_rule():
    information = request.data
    information = information.decode("utf-8").replace("\"", "")
    information = information.replace("[", "")
    information = information.replace("]", "").split(",")
    ruleId = information[0]
    index = int(information[1])
    path = VulGroupByRule.get(ruleId)[index].get("locations")[0].get("physicalLocation").get(
        "artifactLocation").get("uri").split('///')[1].replace("/", "\\")
    f = codecs.open(path, "r", encoding="utf-8-sig")
    tmp = {}
    tmp["content"] = f.read()

    f.close()
    tmp["grRule"] = VulGroupByRule.get(ruleId)[index]
    extension = path.split("\\")[-1].split(".")[-1].lower()

    tmp["language"] = extensionLang.get(extension, "html")

    return jsonify(tmp)

@app.route('/getVulGroupByLocationData', methods=['GET', 'POST'])
def data_get_location():
    information = request.data
    information = information.decode("utf-8").replace("\"", "")
    information = information.replace("[", "")
    information = information.replace("]", "").split(",")
    fileNameid = information[0]
    index = int(information[1])

    path = VulGroupByLocation.get(fileNameid)[index].get("locations")[0].get("physicalLocation").get(
        "artifactLocation").get("uri").split('///')[1].replace("/", "\\")
    f = codecs.open(path, "r", encoding="utf-8-sig")

    tmp = {}
    tmp["content"] = f.read()
    f.close()
    tmp["grLocation"] = VulGroupByLocation.get(fileNameid)[index]
    extension = path.split("\\")[-1].split(".")[-1].lower()

    tmp["language"] = extensionLang.get(extension, "html")
    return jsonify(tmp)


@app.route('/result')
def result():

    sarifPath = request.args.get("sarifPath")
    f = open(sarifPath, "r")

    sarif_data = loader.load_sarif_file(sarifPath)

    Location = set()
    Rule = set()

    VulNumber = sarif_data.get_result_count()

    ResultList = sarif_data.data.get("runs")[0].get("results")

    for i in ResultList:
        Location.add(i.get("locations")[0].get(
            "physicalLocation").get("artifactLocation").get("uri"))

    for i in ResultList:
        Rule.add(i.get("ruleId"))

    ListRule = list(Rule)
    ListLocation = list(Location)

    filename = []
    for i in ListLocation:
        tmp = i.split("/")[-2:]
        filename.append("/".join(tmp))

    lenkey = len(filename)
    lenListRule = len(ListRule)
    for i in range(lenkey):
        tmp = {}
        tmp[filename[i]] = []
        for j in range(VulNumber):
            if ListLocation[i] == ResultList[j].get("locations")[0].get("physicalLocation").get("artifactLocation").get("uri"):
                tmp[filename[i]].append(ResultList[j])
        VulGroupByLocation.update(tmp)

    for i in range(lenListRule):
        tmp = {}
        tmp[ListRule[i]] = []
        for j in range(VulNumber):
            if ListRule[i] == ResultList[j].get("ruleId"):
                tmp[ListRule[i]].append(ResultList[j])

        VulGroupByRule.update(tmp)

    content = f.read()

    language = "json"

    ListRule = list(Rule)
    
    f.close()
    return render_template("result.html", VulNumber=VulNumber, mapRuleIdRuleName=mapRuleIdRuleName,
                           ListRule=ListRule, len=lenkey, VulGroupByLocation=VulGroupByLocation, VulGroupByRule=VulGroupByRule,
                           lenListRule=lenListRule, filename=filename, content=content, language=language)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
