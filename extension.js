const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

function activate(context) {
    console.log('Depscan extension is now active!');

    const disposable = vscode.commands.registerCommand('depscan.scanDependencies', async function () {
        vscode.window.showInformationMessage('Starting dependency scan...');
    
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('No workspace folder is open.');
            return;
        }
    
        const workspacePath = workspaceFolders[0].uri.fsPath;
        const results = {
            python: 'No requirements.txt found',
            node: 'No package.json found',
            rust: 'No Cargo.toml found',
            go: 'No go.mod found',
            ruby: 'No Gemfile.lock found',
            cpp: 'No Makefile or CMakeLists.txt found',
            vulnerabilities: {},
            javaVulnerabilities: [],
            pythonVulnerabilities: [],
            nodeVulnerabilities: [],
            rustVulnerabilities: [],
            goVulnerabilities: [],
            rubyVulnerabilities: [],
            cppVulnerabilities: [],
        };
        
        // Check for go.mod
        const goModPath = path.join(workspacePath, 'go.mod');
        if (fs.existsSync(goModPath)) {
            results.go = `Found go.mod at ${goModPath}`;
            results.goVulnerabilities = await scanGoDependencies(workspacePath);
        }
        
        // Check for Gemfile.lock
        const gemfilePath = path.join(workspacePath, 'Gemfile.lock'); // Removed extra space before 'Gemfile.lock'
        if (fs.existsSync(gemfilePath)) {
            results.ruby = `Found Gemfile.lock at ${gemfilePath}`;
            results.rubyVulnerabilities = await scanRubyDependencies(workspacePath);
        }
        // Check for pom.xml
const pomXmlPath = path.join(workspacePath, 'pom.xml');
if (fs.existsSync(pomXmlPath)) {
    results.java = `Found pom.xml at ${pomXmlPath}`;
    results.javaVulnerabilities = await scanJavaDependencies(workspacePath);
}
         // Check for C/C++ dependencies
         const cppResults = await scanCppDependencies(workspacePath);
         results.cpp = cppResults.length > 0 ? 'C/C++ scan completed' : 'No C/C++ files detected';
         results.cppVulnerabilities = cppResults;
    
        // Check for requirements.txt
        const requirementsPath = path.join(workspacePath, 'requirements.txt');
        if (fs.existsSync(requirementsPath)) {
            results.python = `Found requirements.txt at ${requirementsPath}`;
            results.pythonVulnerabilities = await scanPythonDependencies(requirementsPath);
        }
    
        // Check for package.json
        const packageJsonPath = path.join(workspacePath, 'package.json');
        if (fs.existsSync(packageJsonPath)) {
            results.node = `Found package.json at ${packageJsonPath}`;
            results.nodeVulnerabilities = await scanNodeDependencies(workspacePath);
        }
    
        // Check for Cargo.toml
        const cargoTomlPath = path.join(workspacePath, 'Cargo.toml');
        if (fs.existsSync(cargoTomlPath)) {
            results.rust = `Found Cargo.toml at ${cargoTomlPath}`;
            results.rustVulnerabilities = await scanRustDependencies(workspacePath);
        }
    
        // Display results
        const panel = vscode.window.createWebviewPanel(
            'depscan',
            'Dependency Scan Results',
            vscode.ViewColumn.One,
            {}
        );
    
        panel.webview.html = getWebviewContent(results);
    });
    context.subscriptions.push(disposable);
} 

function scanCppDependencies(workspacePath) {
    return new Promise((resolve) => {
        const makefilePath = path.join(workspacePath, 'Makefile');
        const cmakeListsPath = path.join(workspacePath, 'CMakeLists.txt');

        if (!fs.existsSync(makefilePath) && !fs.existsSync(cmakeListsPath)) {
            resolve([{ package: 'Error', version: 'N/A', vulnerabilities: ['No Makefile or CMakeLists.txt found'], severity: 'Error' }]);
            return;
        }

        // Use cppcheck for static analysis
        const cmd = `cppcheck --enable=all --xml --output-file=cppcheck_results.xml ${workspacePath}`;
        exec(cmd, { cwd: workspacePath, shell: true }, (error, stdout, stderr) => {
            if (error) {
                resolve([{ package: 'Error', version: 'N/A', vulnerabilities: [`Error running cppcheck: ${stderr || error.message}`], severity: 'Error' }]);
                return;
            }

            const resultFile = path.join(workspacePath, 'cppcheck_results.xml');
            if (fs.existsSync(resultFile)) {
                const xmlContent = fs.readFileSync(resultFile, 'utf8');
                try {
                    const vulnerabilities = parseCppcheckResults(xmlContent);
                    resolve(vulnerabilities);
                } catch (parseError) {
                    resolve([{ package: 'Error', version: 'N/A', vulnerabilities: [`Error parsing cppcheck results: ${parseError.message}`], severity: 'Error' }]);
                }
            } else {
                resolve([{ package: 'Error', version: 'N/A', vulnerabilities: ['No cppcheck results found'], severity: 'Error' }]);
            }
        });
    });
}

function parseCppcheckResults(xmlContent) {
    const parser = require('xml2js').parseString;
    const vulnerabilities = [];

    parser(xmlContent, (err, result) => {
        if (err) {
            throw new Error(`Failed to parse XML: ${err.message}`);
        }

        const errors = result?.results?.errors?.[0]?.error || [];
        errors.forEach((error) => {
            vulnerabilities.push({
                package: error?.['$']?.file || 'Unknown',
                version: 'N/A',
                vulnerabilities: [error?.['$']?.msg || 'No description available'],
                severity: mapCppcheckSeverity(error?.['$']?.severity || 'unknown')
            });
        });
    });

    return vulnerabilities;
}

function mapCppcheckSeverity(severity) {
    switch (severity.toLowerCase()) {
        case 'error':
            return 'High';
        case 'warning':
            return 'Medium';
        case 'style':
        case 'performance':
            return 'Low';
        default:
            return 'Unknown';
    }
}
function scanGoDependencies(workspacePath) {
    return new Promise((resolve) => {
        const goModPath = path.join(workspacePath, 'go.mod');
        if (!fs.existsSync(goModPath)) {
            resolve([]);
        }

        // Run govulncheck with the output redirected
        exec('govulncheck -json ./... 2>&1', { cwd: workspacePath, shell: true }, (error, stdout, stderr) => {
            if (error) {
                resolve([{
                    package: 'Error',
                    version: 'N/A',
                    vulnerabilities: [`Error running govulncheck: ${stderr || error.message}`],
                    severity: 'Error'
                }]);
            } else {
                try {
                    // Clean the output to remove any non-JSON text
                    const output = stdout.trim();
                    const jsonOutput = output.split('\n').filter(line => line.startsWith('{') || line.startsWith('[')).join('\n');

                    // Check if the cleaned output is valid JSON
                    if (jsonOutput) {
                        // Attempt to parse the cleaned JSON output
                        const vulnerabilities = parseGovulncheckOutput(jsonOutput);
                        resolve(vulnerabilities);
                    } else {
                        resolve([{
                            package: 'Error',
                            version: 'N/A',
                            vulnerabilities: ['Output is not valid JSON'],
                            severity: 'Error'
                        }]);
                    }
                } catch (parseError) {
                    resolve([{
                        package: 'Error',
                        version: 'N/A',
                        vulnerabilities: [`Error parsing govulncheck output: ${parseError.message}`],
                        severity: 'Error'
                    }]);
                }
            }
        });
    });
}
// Function to parse the output of govulncheck
const json5 = require('json5');

function parseGovulncheckOutput(output) {
    try {
        const vulnerabilities = json5.parse(output);
        if (Array.isArray(vulnerabilities)) {
            return vulnerabilities.map(vuln => ({
                package: vuln.package || 'Unknown',
                version: vuln.version || 'N/A',
                vulnerabilities: vuln.vulnerabilities || ['No description available'],
                severity: vuln.severity || 'Unknown'
            }));
        } else {
            return [{
                package: vulnerabilities.package || 'Unknown',
                version: vulnerabilities.version || 'N/A',
                vulnerabilities: vulnerabilities.vulnerabilities || ['No description available'],
                severity: vulnerabilities.severity || 'Unknown'
            }];
        }
    } catch (error) {
        console.error(`Error parsing govulncheck output: ${error.message}`);
        return [{
            package: 'Error',
            version: 'N/A',
            vulnerabilities: [`Error parsing output: ${error.message}`],
            severity: 'Error'
        }];
    }
}

// Function to scan Python dependencies

function scanPythonDependencies(requirementsPath) {
    return new Promise((resolve) => {
        if (!fs.existsSync(requirementsPath)) {
            resolve([]);
        }

        // Read the requirements file to get package names
        const requirements = fs.readFileSync(requirementsPath, 'utf-8').split('\n').map(line => line.split('==')[0].trim()).filter(Boolean);

        // Run pip-audit with the requirements file
        exec(`pip-audit -f json -r ${requirementsPath}`, { cwd: path.dirname(requirementsPath) }, (error, stdout, stderr) => {
            if (error) {
                resolve([{
                    package: 'Error',
                    version: 'N/A',
                    vulnerabilities: [`${stderr || error.message}`],
                    severity: 'Error'
                }]);
            } else {
                try {
                    const result = JSON.parse(stdout);
                    const vulnerabilities = [];

                    // Create a map of vulnerabilities for easy lookup
                    const vulnMap = {};
                    result.dependencies.forEach(dep => {
                        const { name, version, vulns } = dep;
                        vulnMap[name] = {
                            version,
                            vulns: vulns.map(vuln => ({
                                id: vuln.id,
                                description: vuln.description,
                                fix_versions: vuln.fix_versions.join(', '),
                                aliases: vuln.aliases.join(', ')
                            }))
                        };
                    });

                    // Iterate through the requirements to match with vulnerabilities
                    requirements.forEach(pkg => {
                        if (vulnMap[pkg]) {
                            const { version, vulns } = vulnMap[pkg];
                            if (vulns.length > 0) {
                                vulns.forEach(vuln => {
                                    vulnerabilities.push({
                                        package: pkg,
                                        version: version,
                                        vulnerabilities: [
                                            `ID: ${vuln.id}, Description: ${vuln.description}, Fix Versions: ${vuln.fix_versions}, Aliases: ${vuln.aliases}`
                                        ],
                                        severity: 'High' // You can adjust severity based on your criteria
                                    });
                                });
                            } else {
                                vulnerabilities.push({
                                    package: pkg,
                                    version: version,
                                    vulnerabilities: ['No known vulnerabilities'],
                                    severity: 'None'
                                });
                            }
                        } else {
                            vulnerabilities.push({
                                package: pkg,
                                version: 'N/A',
                                vulnerabilities: ['Not found in pip-audit results'],
                                severity: 'None'
                            });
                        }
                    });

                    resolve(vulnerabilities);
                } catch (parseError) {
                    resolve([{
                        package: 'Error',
                        version: 'N/A',
                        vulnerabilities: [`Error parsing pip-audit output: ${parseError.message}`],
                        severity: 'Error'
                    }]);
                }
            }
        });
    });
}

// Function to scan Ruby dependencies
function scanRubyDependencies(workspacePath) {
    return new Promise((resolve) => {
        const gemfilePath = path.join(workspacePath, 'Gemfile.lock');
        if (!fs.existsSync(gemfilePath)) {
            resolve([]);
        }

        exec('bundler-audit check', { cwd: workspacePath }, (error, stdout, stderr) => {
            if (error) {
                resolve([{
                    package: 'Error',
                    version: 'N/A',
                    vulnerabilities: [`Error running bundle audit: ${stderr || error.message}`],
                    severity: 'Error'
                }]);
            } else {
                try {
                    const auditResults = JSON.parse(stdout);
                    const vulnerabilities = auditResults.vulnerabilities.map(vuln => ({
                        package: vuln.gem_name,
                        version: vuln.version,
                        vulnerabilities: [vuln.advisory],
                        severity: vuln.severity || 'Unknown'
                    }));
                    resolve(vulnerabilities);
                } catch (parseError) {
                    resolve([{
                        package: 'Error',
                        version: 'N/A',
                        vulnerabilities: [`Error parsing bundle audit output: ${parseError.message}`],
                        severity: 'Error'
                    }]);
                }
            }
        });
    });
}

// Function to scan Node.js dependencies
function scanNodeDependencies(workspacePath) {
    return new Promise((resolve) => {
        exec('npm audit --json', { cwd: workspacePath }, (error, stdout, stderr) => {
            if (error && !stdout) {
                resolve([{
                    package: 'Error',
                    version: 'N/A',
                    vulnerabilities: [`Error running npm audit: ${stderr || error.message}`],
                    severity: 'Error'
                }]);
            } else {
                try {
                    const auditResults = JSON.parse(stdout);
                    const vulnerabilities = [];

                    if (auditResults.vulnerabilities) {
                        Object.entries(auditResults.vulnerabilities).forEach(([packageName, details]) => {
                            const vulns = Array.isArray(details.via) ? details.via : [details.via];
                            vulnerabilities.push({
                                package: packageName,
                                version: details.version,
                                vulnerabilities: vulns.map(v => 
                                    typeof v === 'string' ? v : 
                                    `${v.title || v.name}: ${v.url || 'No details available'}`
                                ),
                                severity: details.severity || 'Unknown'
                            });
                        });
                    }

                    resolve(vulnerabilities);
                } catch (parseError) {
                    resolve([{
                        package: 'Error',
                        version: 'N/A',
                        vulnerabilities: [`Error parsing npm audit output: ${parseError.message}`],
                        severity: 'Error'
                    }]);
                }
            }
        });
    });
}
function scanJavaDependencies(workspacePath) {
    return new Promise((resolve) => {
        const fs = require('fs');
        const path = require('path');
        const javaDependenciesPath = path.join(workspacePath, 'pom.xml');
        if (!fs.existsSync(javaDependenciesPath)) {
            resolve([{
                package: 'Error',
                version: 'N/A',
                vulnerabilities: ['No pom.xml file found'],
                severity: 'Error'
            }]);
        } else {
            exec('mvn dependency-check:check', { cwd: workspacePath }, (error, stdout, stderr) => {
                if (error) {
                    resolve([{
                        package: 'Error',
                        version: 'N/A',
                        vulnerabilities: [`Error running dependency-check: ${stderr || error.message}`],
                        severity: 'Error'
                    }]);
                } else {
                    const reportPath = path.join(workspacePath, 'target/dependency-check-report.html');
                    if (fs.existsSync(reportPath)) {
                        const reportContent = fs.readFileSync(reportPath, 'utf8');
                        try {
                            const vulnerabilities = parseDependencyCheckReport(reportContent);
                            resolve(vulnerabilities);
                        } catch (parseError) {
                            resolve([{
                                package: 'Error',
                                version: 'N/A',
                                vulnerabilities: [`Error parsing dependency-check report: ${parseError.message}`],
                                severity: 'Error'
                            }]);
                        }
                    } else {
                        resolve([{
                            package: 'Error',
                            version: 'N/A',
                            vulnerabilities: ['No report found'],
                            severity: 'Error'
                        }]);
                    }
                }
            });
        }
    });
}

function parseDependencyCheckReport(reportContent) {
    const cheerio = require('cheerio');
    const $ = cheerio.load(reportContent);
    const vulnerabilities = [];

    $('table.dependency-table tr').each((index, row) => {
        if (index > 0) {
            const columns = $(row).find('td');
            const packageName = $(columns[0]).text().trim();
            const packageVersion = $(columns[1]).text().trim();
           // const vulnerabilityId = $(columns[2]).text().trim();
            const vulnerabilityDescription = $(columns[3]).text().trim();
            const vulnerabilitySeverity = $(columns[4]).text().trim();

            vulnerabilities.push({
                package: packageName,
                version: packageVersion,
                vulnerabilities: [vulnerabilityDescription],
                severity: vulnerabilitySeverity
            });
        }
    });

    return vulnerabilities;
}

// Function to scan Rust dependencies
function scanRustDependencies(workspacePath) {
    return new Promise((resolve) => {
        exec('cargo audit --json', { cwd: workspacePath }, (error, stdout, stderr) => {
            if (error && !stdout) {
                resolve([{
                    package: 'Error',
                    version: 'N/A',
                    vulnerabilities: [`Error running cargo audit: ${stderr || error.message}`],
                    severity: 'Error'
                }]);
            } else {
                try {
                    const auditResults = JSON.parse(stdout);
                    const vulnerabilities = [];

                    if (auditResults.vulnerabilities && auditResults.vulnerabilities.list) {
                        auditResults.vulnerabilities.list.forEach(vuln => {
 vulnerabilities.push({
                                package: vuln.package.name,
                                version: vuln.package.version,
                                vulnerabilities: [vuln.advisory.description || 'No description available'],
                                severity: vuln.advisory.severity || 'Unknown'
                            });
                        });
                    }

                    resolve(vulnerabilities);
                } catch (parseError) {
                    resolve([{
                        package: 'Error',
                        version: 'N/A',
                        vulnerabilities: [`Error parsing cargo audit output: ${parseError.message}`],
                        severity: 'Error'
                    }]);
                }
            }
        });
    });
}

// Function to generate WebView content
function getWebviewContent(results) {
    let javaTable, pythonTable, nodeTable, rustTable, goTable, rubyTable,cppTable;

    if (results.javaVulnerabilities && results.javaVulnerabilities.length > 0) {
        javaTable = generateTable(results.javaVulnerabilities, 'Java');
    } else {
        javaTable = '<p>No vulnerabilities found for Java dependencies.</p>';
    }

    if (results.pythonVulnerabilities && results.pythonVulnerabilities.length > 0) {
        pythonTable = generateTable(results.pythonVulnerabilities, 'Python');
    } else {
        pythonTable = '<p>No vulnerabilities found for Python dependencies.</p>';
    }

    if (results.nodeVulnerabilities && results.nodeVulnerabilities.length > 0) {
        nodeTable = generateTable(results.nodeVulnerabilities, 'Node.js');
    } else {
        nodeTable = '<p>No vulnerabilities found for Node.js dependencies.</p>';
    }

    if (results.rustVulnerabilities && results.rustVulnerabilities.length > 0) {
        rustTable = generateTable(results.rustVulnerabilities, 'Rust');
    } else {
        rustTable = '<p>No vulnerabilities found for Rust dependencies.</p>';
    }

    if (results.goVulnerabilities && results.goVulnerabilities.length > 0) {
        goTable = generateTable(results.goVulnerabilities, 'Go');
    } else {
        goTable = '<p>No vulnerabilities found for Go dependencies.</p>';
    }
    if (results.cppVulnerabilities && results.cppVulnerabilities.length > 0) {
        cppTable = generateTable(results.cppVulnerabilities, 'C/C++');
    } else {
        cppTable = '<p>No vulnerabilities found for C/C++ dependencies.</p>';
    }
    if (results.rubyVulnerabilities && results.rubyVulnerabilities.length > 0) {
        rubyTable = generateTable(results.rubyVulnerabilities, 'Ruby');
    } else {
        rubyTable = '<p>No vulnerabilities found for Ruby dependencies.</p>';
    }
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Dependency Scan Results</title>
            <style>
                body {
                    font-family: 'Arial', sans-serif;
                    line-height: 1.6;
                    padding: 20px;
                    max-width: 1200px;
                    margin: 0 auto;
                    background: #f4f4f4;
                }
                h1 {
                    color: #555;
                    border-bottom: 2px solid #28a745;
                    padding-bottom: 8px;
                    margin-bottom: 24px;
                }
                h2 {
                    color: #555;
                    margin-top: 24px;
                    margin-bottom: 16px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 24px;
                    background: white;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    border-radius: 8px;
                }
                th, td {
                    text-align: left;
                    padding: 12px 16px;
                    border-bottom: 1px solid #e1e4e8;
                    color: #333; /* Dark gray text color for visibility */
                }
                th {
                    background: #28a745;
                    color: white; /* White text for header row */
                    font-weight: 600;
                }
                tr:nth-child(even) {
                    background: #f9f9f9;
                }
                tr:hover {
                    background: #f1f1f1;
                }
                .vulnerability-ranking {
                    font-weight: 600;
                    padding: 4px 8px;
                    border-radius: 4px;
                    display: inline-block;
                    min-width: 80px;
                    text-align: center;
                }
                .critical {
                    background: #d32f2f;
                    color: white;
                }
                .high {
                    background: #ffeb3b;
                    color: #d32f2f;
                }
                .medium {
                    background: #ff9800;
                    color: white;
                }
                .low {
                    background: #c8e6c9;
                    color: #388e3c;
                }
                .unknown {
                    background: #f0f0f0;
                    color: #757575;
                }
                p {
                    color: #555;
                    padding: 16px;
                    background: #f9f9f9;
                    border-radius: 6px;
                    margin: 16px 0;
                }
                .vulnerability-details {
                    margin: 4px 0;
                    padding: 8px;
                    background: #f9f9f9;
                    border-radius: 4px;
                    font-size: 0.9em;
                    color: #333; /* Ensure text is visible in details */
                }
            </style>
        </head>
        <body>
        <h1>Dependency Scan Results</h1>
            <h2>Rust Dependencies</h2>
            ${rustTable}
            <h2>Node.js Dependencies</h2>
            ${nodeTable}
             <h2>C/C++ Dependencies</h2>
            ${cppTable}
            <h2>Python Dependencies</h2>
            ${pythonTable}
            <h2>Java Dependencies</h2>
            ${javaTable}
            <h2>Go Dependencies</h2>
            ${goTable}
            <h2>Ruby Dependencies</h2>
            ${rubyTable}
            

        </body>
        </html>
    `;
}

// Function to generate table
function generateTable(vulnerabilities, type) {
    if (vulnerabilities.length === 0) {
        return `<p>No vulnerabilities found for ${type} dependencies.</p>`;
    }

    let table = `
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Vulnerabilities</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    vulnerabilities.forEach(dep => {
        const vulnList = dep.vulnerabilities.map(vuln => 
 `<div class="vulnerability-details">${vuln}</div>`
        ).join('');
        
        table += `
            <tr>
                <td><strong>${dep.package}</strong></td>
                <td>${dep.version || 'N/A'}</td>
                <td>${vulnList}</td>
                <td><span class="vulnerability-ranking ${(dep.severity || 'unknown').toLowerCase()}">${dep.severity || 'Unknown'}</span></td>
            </tr>
        `;
    });

    table += `
            </tbody>
        </table>
    `;
    
    return table;
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};