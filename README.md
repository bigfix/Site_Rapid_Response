# RepositorySiteExample
Example of a Repository Site, that could be gathered by BigFix 11.0.7 or later

This repository is intended to be an example, illustrating a possible directory structure layout for a Bigfix Repository Site, with example fixlets, and demonstrating use of siteConfig.xml, site.xml, and digest.xml

See Also:

[BigFix Repository Sites Documentation](https://help.hcl-software.com/bigfix/11.0/platform/Platform/Config/c_repository_site.html)

[BigFix Developer Site](https://developer.bigfix.com)

[BigFix Forum](https://forum.bigfix.com)


# Generating SSH Credential on BigFix Root Server

Open an Elevated Command Prompt
Navigate to the 'RepositorySiteGather\GitCredentials' directory beneath the BES Server directory, i.e.

```
CD "C:\Program Files (x86)\BigFix Enterprise\BES Server\RepositorySiteGather\GitCredentials"
```

Generate an SSH Public/Private Key Pair.  (As of 11.0.7, these specific filenames must be used):
```
# create id_rsa and id_rsa.pub
ssh-keygen -m PEM -t rsa -b 4096 -f id_rsa -N ""
```

Create the known_hosts file.  This example is for github.com, replace with your own git provider as necessary:
```
ssh-keyscan github.com >> known_hosts
```
**Note** : the ssh-keyscan from Windows may not be compatible and yield errors such as
```
 ssh-keyscan github.com >> known_hosts
# github.com:22 SSH-2.0-0e0c9ec
choose_kex: unsupported KEX method sntrup761x25519-sha512@openssh.com
# github.com:22 SSH-2.0-0e0c9ec
choose_kex: unsupported KEX method sntrup761x25519-sha512@openssh.com
# github.com:22 SSH-2.0-0e0c9ec
choose_kex: unsupported KEX method sntrup761x25519-sha512@openssh.com
# github.com:22 SSH-2.0-0e0c9ec
choose_kex: unsupported KEX method sntrup761x25519-sha512@openssh.com
# github.com:22 SSH-2.0-0e0c9ec
choose_kex: unsupported KEX method sntrup761x25519-sha512@openssh.com
```

In that case, install 'Git for Windows' client and use the openssh binaries from it:
```
"C:\Program Files\Git\usr\bin\ssh-keyscan.exe" github.com >> known_hosts
# github.com:22 SSH-2.0-0e0c9ec
# github.com:22 SSH-2.0-0e0c9ec
# github.com:22 SSH-2.0-0e0c9ec
# github.com:22 SSH-2.0-0e0c9ec
# github.com:22 SSH-2.0-0e0c9ec
```



Import the id_rsa.pub as an SSH Public Key on a github account as which your server will authenticate.  This account needs contents:read permission on any repository you wish to gather.

# Content Site Structure

Repositories must follow BigFix Support Site Propagation conventions:

An example directory structure may be illustrated as
```none
Fixlets/
   ├── Analyses/
   │    ├─ digest.xml
   │    └─ 1300- Some Analysis.bes
   ├── Fixlets/
   │    ├── digest.xml
   │    ├── FixletType1/
   │    │     └─ digest.xml
   │    │     └─ 2110- Some Fixlet.bes
   │    └─ FixletType2/
   |          └─ 2210- Some Fixlet.bes
   └── Tasks/
        └─ 3300- Some Task.bes
NonClientFiles/
   ├── customdashboard.ojo
   └── customwebreport.beswrpt

OtherFiles/
   └── mycustomfile.json
site.xml
siteConfig.xml
```

/Fixlets/ — all .bes files (Fixlets, Tasks, Analyses). 
    Subdirectories auto-compile: Fixlets/Analyses/ → Analyses.fxf.
    Sub-Sub-Directories become Digests within an FXF, i.e. Fixlets.fxf contains digests for FixletType1 and FixletType2

/NonClientFiles/ — server-side assets, scripts, metadata (optional).

/OtherFiles/ — Files to be gathered by the client (optional).

/site.xml — global relevance rules applied to all Fixlets (optional); and used as Site Level Relevance.

/siteConfig.xml — customize default directory names (optional).

Filename convention: start with numeric ID, hyphen, space, filename --> '1- Task1.bes', '42- Fixlet Name.bes'.
The numeric ID portion of a filename becomes the Fixlet ID.
Filenames without a numeric ID, or duplicate numeric IDs, will not be gathered on the BigFix Server and will show a warning in the server logs.

# Add Repository Site using BigFix Console
In BigFix Console, go to Tools > Create Repository Site.

Enter the SSH URL: git@github.com:username/repo-name.git

Specify the branch to track (typically 'main' or 'master').

Optionally set a name and description for the site.

BigFix will verify SSH access using the keys in GitCredentials, then clone the repository.

Monitor the root server logs for messages like 'Repository site cloned successfully' or 'Repository site updated successfully'.

# Common Problems

## Gather fails due to untrusted certificate
By default the Root Server's certificate does not contain a Subject Alternative Name value for `IP:127.0.0.1` and the loopback gather does not verify the certificate.  If `_BESGather_Use_Https` is set to `1` (Force HTTPS), the Gather fails entirely.
To workaround, either set `_BESGather_Use_Https` to `2` (Try HTTPS but allow HTTP fallback), or provision a custom certificate for the root server, including a Subject Alternative Name `IP:127.0.0.1`

## Fixlet Naming
Fixlets must be named with a unique numeric prefix and hyphen and an extension of ".bes", i.e. "123- Example Fixlet.bes".  The numeric prefix will determine the Fixlet ID assigned when the Content Site is generated.  BES files with no numeric identifier, or identifiers that are duplicated within the site, will be excluded from the site build and trigger a warning in the log file.

## Embedded JavaScript Comments
JavaScript may be embedded in the Description field of fixlets.
The entire Description is compiled into a single line by the site propagation tool; JavaScript comment to end-of-line, `// comment`, will break JavaScript processing.  These should be replaced by `/* comment */` comments.

## Long File Names
By default Windows has a rather short maximum path limitation, and gathering a Git Repo beneath a deep directory like `C:\Program Files (x86)\BigFix Enterprise\BES Server\RepositorySiteGather\Sites\MyCustomSiteName` can exceed the depth limit.  This results in a message such as the following:


`Fri, 02 Oct 2026 23:39:38 +0200 - 12152 - Failed to sync repository site git@github.com:acapasso/AACBigFix.git: path too long: 'C:/Program Files/BigFix Enterprise/BES Server/RepositorySiteGather/Sites/MySiteName_main_e4fe1019/Source/Fixlets/Tasks/00003546- Some Task With A VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY VERY Long Filename.bes'`

To work around this in BigFix 11.0.7 you must rename the content Filenames or Directory Structure such that the entire file pathname, when prefixed by your BigFix Server Installation Path, does not exceed 260 characters.  A fix for this is expected in future release.

## Cannot propogate custom content using `GroupRelevance`

Custom Fixlets may be configured with Relevance based on other Global Properties from the specific deployment.  This results in a `<GroupRelevance>` node, such as:

```
<GroupRelevance JoinByIntersection="false">
    <SearchComponentPropertyReference PropertyName="OS" Comparison="Contains">
        <SearchText>Win</SearchText>
        <Relevance>exists (operating system) whose (it as string as lowercase contains "Win" as lowercase)</Relevance>
    </SearchComponentPropertyReference>
</GroupRelevance>
```
This is not supported by the Propagation Tools for an External Site or Repository Site, and will generate an error message such as the following:

```
Fri, 02 Oct 2026 11:46:10 +0200 - 12152 - Failed to sync repository site git@github.com:acapasso/AACBigFix.git: Site validation and export failed: E:\Program Files\BigFix Enterprise\BES Server\RepositorySiteGather\Sites\AACBigFix_HX90_e4fe1019\Source\Fixlets\Analyses\20717- BradSexton Detect Source of Pending Restart Status.bes: GroupRelevance clauses in .bes files not supported. Use standard <Relevance> nodes instead.
```

To work around this, you must rewrite the Relevance of the fixlet and avoid using the `<GroupRelevance>` tag.
