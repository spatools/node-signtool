import * as path from "path";
import { spawn, SpawnOptions } from "child_process";

/** Digitally signs files. */
export function sign(file: string | string[], options: SignOptions = { auto: true }, runOptions?: RunOptions): Promise<RunResult> {
    const args = ["sign"];

    if (options.auto) args.push("/a");
    if (options.append) args.push("/as");
    if (options.verify) args.push("/uw");

    if (!undef(options.certificate)) args.push("/f", options.certificate);
    if (!undef(options.password)) args.push("/p", options.password);
    if (!undef(options.issuer)) args.push("/i", options.issuer);
    if (!undef(options.subject)) args.push("/n", options.subject);
    if (!undef(options.rootSubject)) args.push("/r", options.rootSubject);
    if (!undef(options.description)) args.push("/d", options.description);
    if (!undef(options.url)) args.push("/du", options.url);
    if (!undef(options.store)) args.push("/s", options.store);
    if (options.computerStore) args.push("/sm");

    if (!undef(options.sha1)) args.push("/sha1", options.sha1);
    if (!undef(options.csp)) args.push("/csp", options.csp);
    if (!undef(options.key)) args.push("/kc", options.key);

    if (!undef(options.template)) args.push("/c", options.template);
    if (!undef(options.additional)) args.push("/ac", options.additional);
    if (!undef(options.algorithm)) args.push("/fd", options.algorithm);
    if (!undef(options.EKU)) args.push("/u", options.EKU);

    if (!undef(options.timestamp)) args.push("/t", options.timestamp);
    if (!undef(options.rfcTimestamp)) args.push("/tr", options.rfcTimestamp);
    if (!undef(options.timestampAlgo)) args.push("/td", options.timestampAlgo);

    if (!undef(options.digest)) {
        if (typeof options.digest === "boolean") args.push("/dg", ".");
        else args.push("/dg", options.digest);

        if (options.digestXML) args.push("/dxml");
        if (!undef(options.digestFunction)) args.push("/dmdf", options.digestFunction);
    }

    if (!undef(options.digestLib)) args.push("/dlib", options.digestLib);
    if (options.digestOnly) args.push("/ds");

    if (!undef(options.pkcs)) {
        args.push("/p7", options.pkcs);
        if (!undef(options.pkcsCE)) args.push("/p7ce", options.pkcsCE);
        if (!undef(options.pkcsOID)) args.push("/p7co", options.pkcsOID);
    }

    if(options.pageHashes) args.push("/ph");
    if(options.suppresPageHashes) args.push("/nph");

    Array.isArray(file) ? 
        args.push(...file) : 
        args.push(file);

    return run(args, runOptions);
}

/**
 * Verifies the digital signature of files.
 * 
 * The SignTool verify command determines :
 * - whether the signing certificate was issued by a trusted authority,
 * - whether the signing certificate has been revoked, 
 * - and, optionally, whether the signing certificate is valid for a specific policy.
 */
export function verify(file: string | string[], options: VerifyOptions = { useAllMethods: true }, runOptions?: RunOptions): Promise<RunResult> {
    const args = ["verify"];

    if (options.useAllMethods) args.push("/a");
    if (!undef(options.os)) args.push("/o", options.os);
    if (!undef(options.index)) args.push("/ds", options.index.toString());
    if (!undef(options.hash)) args.push("/hash", options.hash);

    if (!undef(options.rootSubject)) args.push("/r", options.rootSubject);
    if (!undef(options.catalogDatabase)) args.push("/ag", options.catalogDatabase);
    if (!undef(options.catalogFile)) args.push("/c", options.catalogFile);
    
    if (options.useDefaultCatalog) args.push("/ad");
    if (options.useDriverCatalog) args.push("/as");
    if (options.verifyAllSignatures) args.push("/all");
    
    if (options.useX64Kernel) args.push("/kp");
    if (options.useMultiSemantics) args.push("/ms");
    if (options.verifyPKCS) args.push("/p7");
    if (options.verifyPageHash) args.push("/ph");
    if (options.verifyTimestamp) args.push("/tw");

    if (options.defaultAuthPolicy) args.push("/pa");
    if (!undef(options.useAuthPolicy)) args.push("/pg", options.useAuthPolicy);

    if (options.showDescription) args.push("/d");
    
    Array.isArray(file) ? 
        args.push(...file) : 
        args.push(file);

    return run(args, runOptions);
}

/** Time stamps files. */
export function timestamp(file: string | string[], options: TimestampOptions, runOptions?: RunOptions): Promise<RunResult> {
    const args = ["timestamp"];

    if (!undef(options.url)) args.push("/t", options.url);
    if (!undef(options.rfcUrl)) args.push("/tr", options.rfcUrl);
    if (!undef(options.sealUrl)) args.push("/tseal", options.sealUrl);
    if (!undef(options.algorithm)) args.push("/td", options.algorithm);
    if (!undef(options.index)) args.push("/tp", options.index.toString());
    if (!undef(options.pkcs)) args.push("/p7", options.pkcs);

    Array.isArray(file) ? 
        args.push(...file) : 
        args.push(file);

    return run(args, runOptions);
}

/** Adds or removes a catalog file to or from a catalog database. */
export function catdb(file: string | string[], options: CatDBOptions = {}, runOptions?: RunOptions): Promise<RunResult> {
    const args = ["catdb"];

    if (options.default) args.push("/d");

    if (!undef(options.guid)) args.push("/g", options.guid);

    if (options.remove) args.push("/r");
    if (options.unique) args.push("/u");

    Array.isArray(file) ? 
        args.push(...file) : 
        args.push(file);

    return run(args, runOptions);
}

export interface SignOptions {
    /**
     * Specifies the signing certificate in a file.
     * Only the Personal Information Exchange (PFX) file format is supported.
     * You can use the PVK2PFX.exe tool to convert SPC and PVK files to PFX format.
     * 
     * If the file is in PFX format protected by a password, use the `password` option to specify the password.
     * If the file does not contain private keys, use the `csp` and `key` options to specify the CSP and private key container name, respectively.
     */
    certificate?: string;
    /** 
     * Specifies the password to use when opening a PFX file.
     * A PFX file can be specified by using the `certificate` option.
     * For information about protecting passwords, see Handling Passwords.
     */
    password?: string;
    /** Specifies the name of the issuer of the signing certificate. This value can be a substring of the entire issuer name. */
    issuer?: string;
    /** Specifies the name of the subject of the signing certificate. This value can be a substring of the entire subject name. */
    subject?: string;
    /**
     * Specifies the name of the subject of the root certificate that the signing certificate must chain to.
     * This value can be a substring of the entire subject name of the root certificate.
     */
    rootSubject?: string;
    /** Specifies a description of the signed content. */
    description?: string;
    /** Specifies a URL for expanded description of the signed content. */
    url?: string;
    /** Specifies the store to open when searching for the certificate. If this option is not specified, the My store is opened. */
    store?: string;
    /** Specifies that a computer store, instead of a user store, be used. */
    computerStore?: boolean;
    /** Specifies the SHA1 hash of the signing certificate. */
    sha1?: string;
    /** Specifies the cryptographic service provider (CSP) that contains the private key container. */
    csp?: string;
    /** Specifies the key that contains the name of the private key. */
    key?: string;
    
    /** Specifies the Certificate Template Name (a Microsoft extension) for the signing certificate. */
    template?: string;
    /** Specifies a file that contains an additional certificate to add to the signature block. */
    additional?: string;
    /**
     * Specifies the file digest algorithm to use to create file signatures. The default algorithm is Secure Hash Algorithm (SHA-1).
     * Windows Vista and earlier:  This flag is not supported.
     */
    algorithm?: string;
    /**
     * Specifies the enhanced key usage (EKU) that must be present in the signing certificate.
     * The usage value can be specified by OID or string.
     * The default usage is "Code Signing" (1.3.6.1.5.5.7.3.3).
     */
    EKU?: string;

    /**
     * Specifies the URL of the time stamp server.
     * If this option is not present, then the signed file will not be time stamped.
     * A warning is generated if time stamping fails.
     */
    timestamp?: string;
    /**
     * Specifies the RFC 3161 time stamp server's URL.
     * If this option (or `timestamp`) is not specified, the signed file will not be time stamped.
     * A warning is generated if time stamping fails.
     * This switch cannot be used with the `timestamp` switch.
     */
    rfcTimestamp?: string;
    /** Used with the `rfcTimestamp` switch to request a digest algorithm used by the RFC 3161 time stamp server. */
    timestampAlgo?: string;

    /**
     * Generates the to be signed digest and the unsigned PKCS7 files.
     * The output digest and PKCS7 files will be: Path\FileName.dig and Path\FileName.p7u.
     * To output an additional XML file, see `digestXML`.
     */
    digest?: boolean | string;
    /** 
     * When used with the `digest` option, produces an XML file.
     * The output file will be: Path\FileName.dig.xml.
     */
    digestXML?: boolean;
    /** When used with the `digest` option, passes the file’s contents to the AuthenticodeDigestSign function without modification. */
    digestFunction?: string;

    /**
     * Creates the signature by ingesting the signed digest to the unsigned PKCS7 file.
     * The input signed digest and unsigned PKCS7 files should be: Path\FileName.dig.signed and Path\FileName.p7u.
     */
    useDigest?: string;
    /**
     * Specifies the DLL implementing the AuthenticodeDigestSign function to sign the digest with.
     * This option is equivalent to using SignTool separately with the `digest`, `digestOnly`, and `useDigest` switches, except this option invokes all three as one atomic operation.
     */
    digestLib?: string;
    /** Signs the digest only. The input file should be the digest generated by the `digest` option. The output file will be: File.signed. */
    digestOnly?: string;

    /** Specifies that for each specified content file, a PKCS #7 file is produced. The produced PKCS #7 file is named Path\FileName.p7. */
    pkcs?: string;
    /**
     * Specifies options for the signed PKCS #7 content.
     * Set Value to "Embedded" to embed the signed content in the PKCS #7 file.
     * Set Value to "DetachedSignedData" to produce the signed data portion of a detached PKCS #7 file.
     * If this option is not used, then the default choice is "Embedded".
     */
    pkcsCE?: "Embedded" | "DetachedSignedData";
    /** Specifies the object identifier (OID) that identifies the signed PKCS #7 content. */
    pkcsOID?: string;
    
    /** 
     * Selects the best signing certificate automatically. 
     * If this option is not present, SignTool expects to find only one valid signing certificate.
     */
    auto?: boolean;
    /** Appends this signature. If no primary signature is present, this signature is made the primary signature. */
    append?: boolean;
    /** Specifies using "Windows System Component Verification" (1.3.6.1.4.1.311.10.3.6). */
    verify?: boolean;

    /** If supported, generates page hashes for executable files. This option is ignored for non-PE files. */
    pageHashes?: boolean;
    /**
     * If supported, suppresses page hashes for executable files.
     * The default behavior is determined by the SIGNTOOL_PAGE_HASHES environment variable and by the Wintrust.dll version.
     * This option is ignored for non-PE files.
     */
    suppresPageHashes?: boolean;
}

export interface VerifyOptions {
    /**
     * Specifies that all methods can be used to verify the file.
     * First, the catalog databases are searched to determine whether the file is signed in a catalog.
     * If the file is not signed in any catalog, SignTool attempts to verify the file's embedded signature.
     * 
     * This option is recommended when verifying files that may or may not be signed in a catalog.
     * Examples of files that may or may not be signed include Windows files or drivers.
     */
    useAllMethods?: boolean;

    /**
     * Verifies the file by operating system version. The version parameter is of the form:
     *      PlatformID:VerMajor.VerMinor.BuildNumber
     * 
     * The use of the `os` switch is recommended.
     * If `os` is not specified SignTool may return unexpected results. 
     * For example, if you do not include the `os` switch, then system catalogs that validate
     * correctly on an older OS may not validate correctly on a newer OS.
     */
    os?: string;

    /** Verifies the signature at a certain position. */
    index?: number;
    /** Specifies an optional hash algorithm to use when searching for a file in a catalog. */
    hash?: "SHA1" | "SHA256";

    /**
     * Specifies the name of the subject of the root certificate that the signing certificate must chain to.
     * This value can be a substring of the entire subject name of the root certificate.
     */
    rootSubject?: string;

    /** Finds the catalog in the catalog database identified by the GUID. */
    catalogDatabase?: string;
    /** Specifies the catalog file by name. */
    catalogFile?: string

    /** Finds the catalog by using the default catalog database. */
    useDefaultCatalog?: boolean;
    /** Finds the catalog by using the system component (driver) catalog database. */
    useDriverCatalog?: boolean;
    /** Verifies all signatures in a file with multiple signatures. */
    verifyAllSignatures?: boolean;

    /** Performs the verification by using the x64 kernel-mode driver signing policy. */
    useX64Kernel?: boolean;
    /** Uses multiple verification semantics. This is the default behavior of a WinVerifyTrust call. */
    useMultiSemantics?: boolean;
    /** Verify PKCS #7 files. No existing policies are used for PKCS #7 validation. The signature is checked and a chain is built for the signing certificate. */
    verifyPKCS?: boolean;
    /** Print and verify page hash values. */
    verifyPageHash?: boolean;
    /** Specifies that a warning is generated if the signature is not time stamped. */
    verifyTimestamp?: boolean;

    /**
     * Specifies that the Default Authentication Verification Policy is used.
     * If omitted, SignTool uses the Windows Driver Verification Policy.
     * This option cannot be used with the catdb options.
     */
    defaultAuthPolicy?: boolean;
    /**
     * Specifies a verification policy by GUID.
     * The GUID corresponds to the ActionID of the verification policy.
     * This option cannot be used with the catdb options.
     */
    useAuthPolicy?: string;

    /** Print the description and description URL. */
    showDescription?: boolean;
}

export interface TimestampOptions {
    /**
     * The file being time stamped must have previously been signed.
     * Either the `url`, the `rfcUrl` or the `sealUrl` option is required.
     */
    url?: string;
    /**
     * Specifies the RFC 3161 time stamp server's URL.
     * The file being time stamped must have previously been signed.
     * Either the `url`, the `rfcUrl` or the `sealUrl` option is required.
     */
    rfcUrl?: string;
    /**
     * Specifies the RFC 3161 timestamp server's URL for timestamping a Sealed file.
     * Either the `url`, the `rfcUrl` or the `sealUrl` option is required.
     */
    sealUrl?: string;
    /** Used with the `rfcUrl` switch to request a digest algorithm used by the RFC 3161 time stamp server. */
    algorithm?: string;
    /** Adds a timestamp to the signature at index. */
    index?: number;
    /** Adds a timestamp to PKCS #7 files. */
    pkcs?: string;
}

export interface CatDBOptions {
    /**
     * Specifies that the default catalog database be updated.
     * If neither the `default` nor `guid` option is used, SignTool updates the system component and driver database.
     */
    default?: boolean;
    /** Specifies that the catalog database identified by the GUID be updated. */
    guid?: string;
    /** 
     * Removes the specified catalog from the catalog database.
     * If this option is not specified, SignTool will add the specified catalog to the catalog database.
     */
    remove?: boolean;
    /**
     * Specifies that a unique name be automatically generated for the added catalog files.
     * If necessary, the catalog files are renamed to prevent name conflicts with existing catalog files.
     * If this option is not specified, SignTool overwrites any existing catalog that has the same name as the catalog being added.
     */
    unique?: boolean;
}

export interface RunOptions {
    /** No output on success and minimal output on failure. */
    quiet?: boolean;
    /** Print verbose success and status messages. This may also provide slightly more information on error. */
    verbose?: boolean;
    /** Display additional debug information. */
    debug?: boolean;

    /** The current working directory to execute SignTool binary on. */
    cwd?: string;
    /** The inner spawn stdio option. */
    stdio?: string;
}

export interface RunResult {
    /** The signtool exit code. */
    code: number;
    /** The signtool stdout content. */
    stdout: string;
    /** The signtool stderr content. */
    stderr: string;
}

export type RunError = Error & RunResult;

function run(args: string[], options: RunOptions = {}): Promise<RunResult> {
    return new Promise<RunResult>((resolve, reject) => {
        let cmd = signtool();
        if (process.platform !== "win32") {
            args.unshift(cmd);
            cmd = "wine";
        }

        if (options.debug) args.unshift("/debug");
        if (options.verbose) args.unshift("/v");
        if (options.quiet) args.unshift("/q");

        const childOptions = {} as SpawnOptions;
        if (!undef(options.cwd)) childOptions.cwd = options.cwd;
        if (!undef(options.stdio)) childOptions.stdio = options.stdio;

        const 
            stdout = [] as Buffer[],
            stderr = [] as Buffer[],

            child = spawn(cmd, args, childOptions);

        child.stdout.on("data", data => { stdout.push(data); });
        child.stderr.on("data", data => { stderr.push(data); });

        child.on("error", reject);
        child.on("close", (code) => {
            if (code === 0) {
                return resolve({
                    code,
                    stdout: Buffer.concat(stdout).toString(),
                    stderr: Buffer.concat(stderr).toString()
                });
            }

            const err = new Error(`SignTool ${args[0]} command exited with code ${code}`) as any;
            err.command = cmd;
            err.args = args;
            err.code = code;
            err.stdout = Buffer.concat(stdout).toString();
            err.stderr = Buffer.concat(stderr).toString();
            
            if (err.stderr) {
                err.message = err.message + "\n" + err.stderr;
            }

            reject(err);
        });
    });
}

function undef(val: any): val is undefined {
    return typeof val === "undefined";
}

function signtool(): string {
    if ((<any>signtool).result) return (<any>signtool).result;

    switch(process.arch) {
        case "ia32":
            return ((<any>signtool).result = path.join(__dirname, "signtool", "x86", "signtool.exe"));

        case "x64":
            return ((<any>signtool).result = path.join(__dirname, "signtool", "x64", "signtool.exe"));

        case "arm":
        default:
            throw new Error("Signtool is not supported in this environment");
    }
}
