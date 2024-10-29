import { toByte } from ".";
import { join } from "path";
import { readFileSync } from "fs";

export function readLockFile<T>(filename: string): T {
    const filePath = join(__dirname, "..", "..", "..", "examples", "http", "lockfile", filename);
    const jsonString = readFileSync(filePath, 'utf-8');
    const jsonData = JSON.parse(jsonString);
    return jsonData;
}

export function getHeaders(data: Request | Response): [string, string][] {
    const headers: [string, string][] = [];
    let i = 1;
    while (true) {
        const nameKey = `headerName${i}`;
        const valueKey = `headerValue${i}`;
        if (nameKey in data && valueKey in data) {
            headers.push([data[nameKey], data[valueKey]]);
            i++;
        } else {
            break;
        }
    }
    return headers;
}

export interface Request {
    method: string,
    target: string,
    version: string,
    [key: string]: string,
}

export interface Response {
    version: string,
    status: string,
    message: string,
    [key: string]: string,
}

export function readHTTPInputFile(filename: string) {
    const filePath = join(__dirname, "..", "..", "..", "examples", "http", filename);
    let data = readFileSync(filePath, 'utf-8');

    let input = toByte(data);

    // Split headers and body, accounting for possible lack of body
    const parts = data.split('\r\n\r\n');
    const headerSection = parts[0];
    const bodySection = parts.length > 1 ? parts[1] : '';

    // Function to parse headers into a dictionary
    function parseHeaders(headerLines: string[]) {
        const headers: { [id: string]: string } = {};

        headerLines.forEach(line => {
            const [key, value] = line.split(/:\s(.+)/);
            if (key) headers[key] = value ? value : '';
        });

        return headers;
    }

    // Parse the headers
    const headerLines = headerSection.split('\r\n');
    const initialLine = headerLines[0].split(' ');
    const headers = parseHeaders(headerLines.slice(1));

    // Parse the body, if JSON response
    let responseBody = {};
    if (headers["content-type"] && headers["content-type"].startsWith("application/json") && bodySection) {
        try {
            responseBody = JSON.parse(bodySection);
        } catch (e) {
            console.error("Failed to parse JSON body:", e);
        }
    }

    // Combine headers and body into an object
    return {
        input: input,
        initialLine: initialLine,
        headers: headers,
        body: responseBody,
        bodyBytes: toByte(bodySection || ''),
    };
}