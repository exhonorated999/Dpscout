import React, { useState } from 'react';
import './ScanDocumentation.css';

type ScanSection = 'device' | 'bitlocker' | 'browser' | 'keywords' | 'hash' | 'intrusion' | 'media';

export const ScanDocumentationPanel: React.FC = () => {
  const [activeSection, setActiveSection] = useState<ScanSection>('device');

  return (
    <div className="scan-documentation">
      <div className="documentation-header">
        <h2>📚 Scan Documentation</h2>
        <p className="documentation-subtitle">
          Understand what each scan module detects and why it matters for your forensic investigation
        </p>
      </div>

      <div className="documentation-layout">
        {/* Sidebar Navigation */}
        <div className="documentation-sidebar">
          <nav className="doc-nav">
            <button
              className={`doc-nav-item ${activeSection === 'device' ? 'active' : ''}`}
              onClick={() => setActiveSection('device')}
            >
              <span className="doc-nav-icon">💻</span>
              <span className="doc-nav-text">Device Information</span>
            </button>
            <button
              className={`doc-nav-item ${activeSection === 'bitlocker' ? 'active' : ''}`}
              onClick={() => setActiveSection('bitlocker')}
            >
              <span className="doc-nav-icon">🔒</span>
              <span className="doc-nav-text">BitLocker Keys</span>
            </button>
            <button
              className={`doc-nav-item ${activeSection === 'browser' ? 'active' : ''}`}
              onClick={() => setActiveSection('browser')}
            >
              <span className="doc-nav-icon">🌐</span>
              <span className="doc-nav-text">Browser History</span>
            </button>
            <button
              className={`doc-nav-item ${activeSection === 'keywords' ? 'active' : ''}`}
              onClick={() => setActiveSection('keywords')}
            >
              <span className="doc-nav-icon">🔍</span>
              <span className="doc-nav-text">Keyword Search</span>
            </button>
            <button
              className={`doc-nav-item ${activeSection === 'hash' ? 'active' : ''}`}
              onClick={() => setActiveSection('hash')}
            >
              <span className="doc-nav-icon">🔐</span>
              <span className="doc-nav-text">Hash Matching</span>
            </button>
            <button
              className={`doc-nav-item ${activeSection === 'media' ? 'active' : ''}`}
              onClick={() => setActiveSection('media')}
            >
              <span className="doc-nav-icon">🖼️</span>
              <span className="doc-nav-text">Media Scanner</span>
            </button>
            <button
              className={`doc-nav-item ${activeSection === 'intrusion' ? 'active' : ''}`}
              onClick={() => setActiveSection('intrusion')}
            >
              <span className="doc-nav-icon">🛡️</span>
              <span className="doc-nav-text">Intrusion Detection</span>
            </button>
          </nav>
        </div>

        {/* Content Area */}
        <div className="documentation-content">
          {activeSection === 'device' && <DeviceInfoDoc />}
          {activeSection === 'bitlocker' && <BitLockerDoc />}
          {activeSection === 'browser' && <BrowserHistoryDoc />}
          {activeSection === 'keywords' && <KeywordSearchDoc />}
          {activeSection === 'hash' && <HashMatchingDoc />}
          {activeSection === 'media' && <MediaScannerDoc />}
          {activeSection === 'intrusion' && <IntrusionDetectionDoc />}
        </div>
      </div>
    </div>
  );
};

// Device Information Documentation
const DeviceInfoDoc: React.FC = () => (
  <div className="doc-section">
    <h3>💻 Device Information Scanner</h3>
    <div className="doc-subsection">
      <h4>What It Scans</h4>
      <p>Collects system-level information about the device being examined:</p>
      <ul>
        <li><strong>Hardware Details:</strong> Computer name, manufacturer, model, serial number</li>
        <li><strong>Operating System:</strong> Windows version, build number, installation date</li>
        <li><strong>User Accounts:</strong> List of all user profiles on the system</li>
        <li><strong>Network Information:</strong> MAC addresses, network adapters, domain membership</li>
        <li><strong>Storage Devices:</strong> Hard drives, USB devices, removable media</li>
      </ul>
    </div>

    <div className="doc-subsection">
      <h4>How It Works</h4>
      <p>
        Uses Windows Management Instrumentation (WMI) and registry queries to gather system information.
        For offline/forensic mode, parses registry hives directly without executing system commands.
      </p>
    </div>

    <div className="doc-subsection">
      <h4>Forensic Value</h4>
      <ul>
        <li><strong>Device Identification:</strong> Positively identify the device in your report</li>
        <li><strong>Ownership Context:</strong> User accounts help establish who had access</li>
        <li><strong>Timeline Establishment:</strong> OS installation date provides temporal boundaries</li>
        <li><strong>Network Activity:</strong> Network info reveals potential online activity</li>
      </ul>
    </div>
  </div>
);

// BitLocker Documentation
const BitLockerDoc: React.FC = () => (
  <div className="doc-section">
    <h3>🔒 BitLocker Encryption &amp; Recovery Keys <span style={{ fontSize: '0.6em', verticalAlign: 'middle', padding: '2px 8px', borderRadius: '10px', background: 'rgba(255,165,0,0.18)', color: 'var(--accent-orange)', border: '1px solid rgba(255,165,0,0.4)' }}>BETA</span></h3>

    <p className="doc-intro">
      BitLocker is Microsoft's built-in full-disk encryption. When it is turned on, everything
      written to the drive is scrambled, and pulling that drive out of the computer gets you
      nothing readable — not files, not deleted data, not even a recognizable file system. The
      only thing that turns it back into evidence is a key.
    </p>

    <div className="doc-callout warning">
      <strong>⏱️ This is the one scan you cannot do later</strong>
      Scout can only ask Windows for a recovery key on a computer that is <strong>powered on
      and already unlocked</strong> — a machine you are sitting in front of at the scene. The
      moment that computer is shut down, the volume re-locks and Windows will no longer hand
      the key over to anyone, including Scout. After that you are down to hoping a copy was
      saved somewhere: a printout, a file on a USB stick, or a backup in your suspect's
      Microsoft account or their employer's Active Directory — none of which you control.
      <strong style={{ marginTop: '12px' }}>Run Scout before you pull the plug.</strong>
    </div>

    <div className="doc-subsection">
      <h4>Step 1: How Scout Decides Whether BitLocker Is On</h4>
      <p>
        Scout asks Windows directly rather than guessing from file extensions. It queries the
        Windows encryption service for every volume on the machine and reads back the real
        protection state, how much of the drive is encrypted, and which encryption method is
        in use.
      </p>
      <p>You will see one of three results, and the difference between them matters:</p>
      <ul>
        <li>
          <strong>BitLocker Not Enabled:</strong> Windows confirmed the drives are not
          encrypted. You can image this machine normally.
        </li>
        <li>
          <strong>BitLocker Enabled:</strong> At least one volume is protected. Scout will
          list each volume and attempt to recover its key (Step 2).
        </li>
        <li>
          <strong>Requires Administrator:</strong> Scout was blocked from looking. Windows
          refuses <em>all</em> BitLocker questions to a program that is not running as
          Administrator — this is a Windows restriction, not a Scout limitation.
        </li>
      </ul>
      <div className="doc-callout warning">
        <strong>⚠️ "Requires Administrator" does NOT mean the drive is unencrypted</strong>
        These two results look similar on screen but mean opposite things. If you see
        "Requires Administrator", click <strong>Relaunch as Administrator</strong> and scan
        again <em>before</em> you conclude anything about this machine's encryption. Treating
        "we were not allowed to look" as "there is no encryption" is how a drive ends up
        unreadable back at the lab.
      </div>
    </div>

    <div className="doc-subsection">
      <h4>Step 2: How Scout Locates the Recovery Key</h4>
      <p>Scout looks in four places, because the key can live in more than one of them:</p>
      <ol>
        <li>
          <strong>Ask Windows for it.</strong> If BitLocker was set up with a recovery
          password, Windows is holding that 48-digit number and will release it to an
          Administrator on the running machine. This is the most reliable source, and it is
          why running elevated matters.
        </li>
        <li>
          <strong>Read the volume's Key ID.</strong> Every protected volume has an
          identifier that ties it to its key. Scout records it so you can prove later that a
          specific key belongs to a specific drive.
        </li>
        <li>
          <strong>Search where people actually save keys.</strong> Many users print or save
          the key when Windows prompts them. Scout sweeps user profiles, Desktop, Documents,
          Downloads, OneDrive folders, and any attached removable drives, looking at{' '}
          <code>.txt</code>, <code>.csv</code>, <code>.rtf</code>, <code>.log</code>,{' '}
          <code>.docx</code>, <code>.xlsx</code> and <code>.BEK</code> files. It reads inside
          Office documents too, not just filenames.
        </li>
        <li>
          <strong>Full Drive Sweep (optional).</strong> A button on the results screen scans
          every attached drive end to end. Slower, but it finds keys saved somewhere unusual.
          You can cancel it at any time.
        </li>
      </ol>

      <div className="doc-subsection">
        <h5>How Scout avoids false positives</h5>
        <p>
          A BitLocker recovery key is not just any 48 digits — it is eight groups of six, and
          every group is mathematically divisible by 11. Scout uses that rule to tell a real
          key from a spreadsheet full of invoice numbers.
        </p>
        <p>
          There is one deliberate exception. If a file's <em>name</em> already announces itself
          (for example <code>BitLocker Recovery Key A1B2C3D4….txt</code>), Scout reports what
          it found even if the digits fail that check, and flags it as unverified. A key that
          was retyped by hand with a typo is still a lead worth having — better on your screen
          with a warning than silently discarded.
        </p>
        <p>
          The same reasoning applies to Key IDs. A Key ID is a GUID, and GUIDs appear in
          ordinary log files, installer records and data exports by the thousand. So in a file
          that has not otherwise identified itself, Scout only records a GUID as a Key ID when
          the surrounding text ties it to BitLocker — the words <code>BitLocker</code> or
          <code>Recovery key</code> near the value, or the label <code>Identifier:</code> in a
          file that mentions BitLocker elsewhere. That is exactly how Windows writes its own
          recovery file. A bare <code>identifier:</code> in an application log is not enough. In
          a file already named for BitLocker, any GUID is taken at face value.
        </p>
      </div>

      <div className="doc-callout info">
        <strong>📄 Recovery keys appear in full</strong>
        Keys are shown complete on screen and printed in full in your PDF report. They are not
        masked or truncated, because a partial key cannot unlock anything. Treat the report as
        sensitive material and handle it under your agency's evidence protocols.
      </div>
    </div>

    <div className="doc-subsection">
      <h4>Step 3: Using the Recovery Key Back at the Lab</h4>
      <p>
        This is what the key is <em>for</em>. Once you have the 48-digit number, you can read
        that drive after it has been removed from the suspect's computer or after that computer
        has been powered off. Work in this order:
      </p>

      <ol>
        <li>
          <strong>Connect the drive through a hardware write blocker.</strong> Do this first,
          every time. When Windows sees a BitLocker volume it will try to interact with it and
          may prompt you for the key on its own — and that interaction can write to your
          evidence. The write blocker is what keeps the original drive untouched.
        </li>
        <li>
          <strong>Image the drive while it is still encrypted.</strong> Take your bit-for-bit
          image normally. The image will look like meaningless data, and that is correct and
          expected. You then unlock the <em>image</em> and leave the original drive alone.
        </li>
        <li>
          <strong>Confirm you are holding the right key.</strong> When Windows or your forensic
          tool asks for a recovery key, it displays a partial Key ID. Match that against the
          Key ID Scout recorded for the volume. If you seized several machines, this is how you
          avoid wasting hours trying the wrong key.
        </li>
        <li>
          <strong>Unlock it.</strong> Either let your forensic suite do it, or use Windows'
          built-in command (see below).
        </li>
      </ol>

      <div className="doc-subsection">
        <h5>Option A — Your forensic software (recommended)</h5>
        <p>
          Most mainstream tools accept a BitLocker recovery password directly and will mount
          the volume read-only, which is exactly what you want. This includes
          <strong> EnCase</strong>, <strong>FTK</strong>, <strong>X-Ways</strong>,
          <strong> Magnet AXIOM</strong>, <strong>Passware</strong>, and
          <strong> Arsenal Image Mounter</strong>. On Linux, the open-source
          <strong> dislocker</strong> tool does the same job. Look for a prompt labelled
          "BitLocker", "recovery password", or "decryption key" and paste the 48-digit number
          from your Scout report.
        </p>
      </div>

      <div className="doc-subsection">
        <h5>Option B — Windows command line</h5>
        <p>
          On a Windows analysis machine, open Command Prompt <strong>as Administrator</strong>.
          Replace <code>X:</code> with the evidence drive letter and paste your key, hyphens
          included:
        </p>
        <code className="code-block wrap">
          manage-bde -unlock X: -RecoveryPassword 111111-222222-333333-444444-555555-666666-777777-888888
        </code>
        <p>Then confirm it worked:</p>
        <code className="code-block wrap">manage-bde -status X:</code>
        <p>
          The volume is now readable and you can work with it in your normal tools. This unlock
          lasts for the current session only — it does <em>not</em> permanently change the
          drive, which is why it is safe for evidence.
        </p>
      </div>

      <div className="doc-callout warning">
        <strong>🚫 Never run <code>manage-bde -off</code> on evidence</strong>
        That command permanently decrypts the drive and rewrites every sector on it. It
        destroys the original state of your evidence and is not reversible. You never need it
        to read a drive — <code>-unlock</code> is sufficient. Similarly, if Windows offers to
        "back up your recovery key" or "manage BitLocker" on the evidence drive, decline.
      </div>

      <div className="doc-subsection">
        <h5>If the drive is damaged and will not unlock</h5>
        <p>
          Windows includes a repair tool that salvages what it can and writes the readable data
          to a <em>separate</em> destination, leaving the damaged original as-is. It requires an
          output location — it will not repair in place:
        </p>
        <code className="code-block wrap">
          repair-bde X: D:\RecoveredImage.img -rp 111111-222222-333333-444444-555555-666666-777777-888888
        </code>
        <p>
          Point the destination at a clean drive with enough free space, never back at the
          evidence drive.
        </p>
      </div>
    </div>

    <div className="doc-subsection">
      <h4>A Note on <code>.BEK</code> Files</h4>
      <p>
        If Scout reports a <code>.BEK</code> file, that is a different kind of key — a
        BitLocker <strong>startup key</strong>, stored as a binary file on a USB stick rather
        than as a number you can read or type. It is used on machines without a TPM chip, where
        the USB stick effectively acts as the ignition key.
      </p>
      <p>
        There is no 48-digit number inside it, so Scout reports the file's existence and its
        Key ID rather than a password. <strong>Seize that USB stick.</strong> To use it, supply
        the file itself:
      </p>
      <code className="code-block wrap">manage-bde -unlock X: -RecoveryKey D:\A1B2C3D4-....BEK</code>
      <p>
        These files are hidden by default, which is why Scout deliberately searches hidden files
        — a normal Explorer window will not show them to you.
      </p>
    </div>

    <div className="doc-subsection">
      <h4>Forensic Value</h4>
      <ul>
        <li><strong>Preserves access to the evidence:</strong> Captures the one piece of information that stops an encrypted seizure from becoming an unreadable brick</li>
        <li><strong>Time-critical capture:</strong> Documents the key while the machine is live, when it is still obtainable</li>
        <li><strong>Ties key to drive:</strong> The recorded Key ID links a specific key to a specific volume for your report</li>
        <li><strong>Finds user-saved copies:</strong> Locates keys the suspect printed or saved to a file, including on removable media</li>
        <li><strong>Documents the encryption itself:</strong> Whether a drive was encrypted, and how thoroughly, can be relevant to intent</li>
      </ul>
    </div>

    <div className="doc-callout info">
      <strong>🧪 Beta feature</strong>
      BitLocker key recovery is new and marked Beta. Detection and the file search are tested,
      but real-world BitLocker configurations vary. Most importantly, not every encrypted volume
      has a 48-digit recovery password attached to it — some are configured with only a TPM or
      startup key. When that is the case Scout will report the volume as encrypted but note that
      no recovery-password protector exists, and the key may only live in the organisation's
      Active Directory, Entra ID, or the owner's Microsoft account. On a corporate or
      school-owned machine, that is a lead worth pursuing with the agency's IT department or a
      warrant. If you hit a configuration Scout handles poorly, please report it.
    </div>
  </div>
);

// Browser History Documentation
const BrowserHistoryDoc: React.FC = () => (
  <div className="doc-section">
    <h3>🌐 Browser History Scanner</h3>
    <div className="doc-subsection">
      <h4>What It Scans</h4>
      <p>Extracts browsing activity from popular web browsers:</p>
      <ul>
        <li><strong>Supported Browsers:</strong> Chrome, Edge, Firefox, Brave, Opera, Vivaldi</li>
        <li><strong>Data Collected:</strong>
          <ul>
            <li>URLs visited and page titles</li>
            <li>Visit timestamps (date and time)</li>
            <li>Visit counts (frequency)</li>
            <li>Bookmarks and favorites</li>
          </ul>
        </li>
        <li><strong>All User Profiles:</strong> Scans browser data for every user account on the system</li>
      </ul>
    </div>

    <div className="doc-subsection">
      <h4>How It Works</h4>
      <p>
        Directly parses browser SQLite databases located in user profile directories. For Chrome-based browsers,
        converts Chrome timestamp format (microseconds since 1601) to standard dates.
      </p>
      <code className="code-block">
        Chrome: C:\Users\[Username]\AppData\Local\Google\Chrome\User Data\Default\History<br/>
        Firefox: C:\Users\[Username]\AppData\Roaming\Mozilla\Firefox\Profiles\[Profile]\places.sqlite
      </code>
    </div>

    <div className="doc-subsection">
      <h4>Forensic Value</h4>
      <ul>
        <li><strong>Online Activity:</strong> Reveals websites visited and search queries</li>
        <li><strong>Intent Evidence:</strong> Search terms can demonstrate knowledge or planning</li>
        <li><strong>Timeline Correlation:</strong> Timestamps help establish user activity periods</li>
        <li><strong>Frequency Analysis:</strong> Visit counts show repeated interest in specific sites</li>
        <li><strong>Account Discovery:</strong> May reveal social media, email, or other online accounts</li>
      </ul>
    </div>

    <div className="doc-callout warning">
      <strong>⚠️ Limitation:</strong> Private/incognito browsing is not captured. Browser history may be cleared by user.
    </div>
  </div>
);

// Keyword Search Documentation
const KeywordSearchDoc: React.FC = () => (
  <div className="doc-section">
    <h3>🔍 Keyword Search Scanner</h3>
    <div className="doc-subsection">
      <h4>What It Scans</h4>
      <p>Searches for user-defined keywords across the file system:</p>
      <ul>
        <li><strong>File Names:</strong> Scans for keywords in file names (fast)</li>
        <li><strong>File Paths:</strong> Includes folder names in search (fast)</li>
        <li><strong>File Contents:</strong> Searches inside text files (slow, optional)</li>
        <li><strong>Supported Locations:</strong> Any drive or folder you select</li>
      </ul>
    </div>

    <div className="doc-subsection">
      <h4>How It Works</h4>
      <p>
        Uses recursive directory traversal with pattern matching:
      </p>
      <ol>
        <li><strong>Load Keywords:</strong> Imports keyword lists from Settings</li>
        <li><strong>Scan Files:</strong> Walks directory tree checking each file</li>
        <li><strong>Match Detection:</strong> Case-insensitive substring matching</li>
        <li><strong>Content Search:</strong> Opens text files (&lt;10MB) and scans line-by-line</li>
        <li><strong>Results:</strong> Returns matching files with context</li>
      </ol>
    </div>

    <div className="doc-subsection">
      <h4>Keyword List Management</h4>
      <p>Create custom keyword lists in <strong>Settings → Keyword Lists</strong>:</p>
      <ul>
        <li>Import lists from JSON files</li>
        <li>Organize by category (e.g., "Drug Terms", "Weapons", "Exploitation")</li>
        <li>Enable/disable lists per scan</li>
        <li>Combine multiple lists in one scan</li>
      </ul>
    </div>

    <div className="doc-subsection">
      <h4>Forensic Value</h4>
      <ul>
        <li><strong>Evidence Location:</strong> Quickly find files related to investigation</li>
        <li><strong>Hidden Content:</strong> Discover files with incriminating names or content</li>
        <li><strong>Communication:</strong> Find chat logs, emails, or documents with key terms</li>
        <li><strong>Planning Evidence:</strong> Locate research files or preparation materials</li>
      </ul>
    </div>

    <div className="doc-callout info">
      <strong>💡 Performance Tip:</strong> Content scanning is much slower than name/path scanning. 
      Use content search only when necessary.
    </div>
  </div>
);

// Hash Matching Documentation
const HashMatchingDoc: React.FC = () => (
  <div className="doc-section">
    <h3>🔐 Hash Matching Scanner</h3>
    <div className="doc-subsection">
      <h4>What It Scans</h4>
      <p>Compares file hashes against known databases of illegal content:</p>
      <ul>
        <li><strong>Hash Types Supported:</strong> MD5, SHA-1, SHA-256</li>
        <li><strong>Database Sources:</strong>
          <ul>
            <li>Project VIC (ICAC - child exploitation materials)</li>
            <li>NCMEC hash lists</li>
            <li>Custom hash lists you import</li>
          </ul>
        </li>
        <li><strong>Capacity:</strong> Handles 14+ million hashes efficiently</li>
      </ul>
    </div>

    <div className="doc-subsection">
      <h4>How It Works</h4>
      <ol>
        <li><strong>Import Hash Database:</strong> Load Project VIC or other lists in Settings → Hash Lists</li>
        <li><strong>Compute File Hashes:</strong> Scanner calculates SHA-256 for each media file</li>
        <li><strong>Database Lookup:</strong> Queries local SQLite database for matches</li>
        <li><strong>Match Reporting:</strong> Files matching known bad hashes are flagged</li>
        <li><strong>Context Provided:</strong> Shows hash type, source list, and category</li>
      </ol>
    </div>

    <div className="doc-subsection">
      <h4>Database Management</h4>
      <p>In <strong>Settings → Hash Lists</strong>:</p>
      <ul>
        <li><strong>Import:</strong> Load large JSON hash databases (Project VIC format)</li>
        <li><strong>Progress Tracking:</strong> Real-time progress for multi-million hash imports</li>
        <li><strong>Statistics:</strong> View total hashes and lists loaded</li>
        <li><strong>Multiple Lists:</strong> Combine multiple sources</li>
        <li><strong>Clear Database:</strong> Remove all hashes and start fresh</li>
      </ul>
    </div>

    <div className="doc-subsection">
      <h4>Forensic Value</h4>
      <ul>
        <li><strong>Positive Identification:</strong> Cryptographically proves file is known contraband</li>
        <li><strong>Court-Ready Evidence:</strong> Hash matching is widely accepted in court</li>
        <li><strong>Fast Triage:</strong> Immediately identify priority evidence</li>
        <li><strong>File Integrity:</strong> Hashes prove files haven't been altered</li>
        <li><strong>Multi-Jurisdictional:</strong> Project VIC hashes recognized internationally</li>
      </ul>
    </div>

    <div className="doc-callout warning">
      <strong>⚠️ Legal Requirement:</strong> Access to Project VIC hash lists requires law enforcement credentials 
      and proper authorization. Handle hash matches with extreme care and follow your agency's protocols.
    </div>
  </div>
);

// Media Scanner Documentation
const MediaScannerDoc: React.FC = () => (
  <div className="doc-section">
    <h3>🖼️ Media File Scanner</h3>
    <div className="doc-subsection">
      <h4>What It Scans</h4>
      <p>Locates and analyzes image and video files:</p>
      <ul>
        <li><strong>Image Formats:</strong> JPG, PNG, GIF, BMP, TIFF, WebP</li>
        <li><strong>Video Formats:</strong> MP4, AVI, MOV, WMV, FLV, MKV</li>
        <li><strong>File Size Limit:</strong> Up to 500MB per file</li>
        <li><strong>Scan Locations:</strong> Common folders (Pictures, Downloads, Videos, Documents)</li>
      </ul>
    </div>

    <div className="doc-subsection">
      <h4>How It Works</h4>
      <ol>
        <li><strong>File Discovery:</strong> Recursively scans selected folders</li>
        <li><strong>Hash Calculation:</strong> Computes SHA-256 for each media file</li>
        <li><strong>Metadata Extraction:</strong> Reads EXIF data (camera, GPS, timestamp)</li>
        <li><strong>Thumbnail Generation:</strong> Creates preview images for quick review</li>
        <li><strong>Hash Matching:</strong> Checks against known hash databases (if enabled)</li>
        <li><strong>Keyword Checking:</strong> Examines file paths for suspicious terms</li>
      </ol>
    </div>

    <div className="doc-subsection">
      <h4>Metadata Captured</h4>
      <ul>
        <li><strong>File Information:</strong> Name, path, size, creation/modification dates</li>
        <li><strong>EXIF Data:</strong> Camera make/model, focal length, ISO, flash</li>
        <li><strong>GPS Coordinates:</strong> Location where photo was taken (if available)</li>
        <li><strong>Timestamps:</strong> Original date taken, file system dates</li>
        <li><strong>Image Properties:</strong> Resolution, dimensions, color depth</li>
      </ul>
    </div>

    <div className="doc-subsection">
      <h4>Forensic Value</h4>
      <ul>
        <li><strong>Evidence Location:</strong> Discover all media on device</li>
        <li><strong>Visual Review:</strong> Gallery view for rapid triage</li>
        <li><strong>Geolocation:</strong> GPS data reveals where photos were taken</li>
        <li><strong>Timeline Establishment:</strong> Photo timestamps show activity periods</li>
        <li><strong>Device Linking:</strong> Camera EXIF links photos to specific devices</li>
        <li><strong>Hash Comparison:</strong> Integration with known contraband databases</li>
      </ul>
    </div>
  </div>
);

// Intrusion Detection Documentation
const IntrusionDetectionDoc: React.FC = () => (
  <div className="doc-section">
    <h3>🛡️ Intrusion Detection Scanner</h3>
    <p className="doc-intro">
      The Intrusion Detection scanner analyzes Windows security artifacts to detect unauthorized access, 
      suspicious account activity, and potential system compromise. This is critical for investigating 
      data breaches, insider threats, and external attacks.
    </p>

    <div className="doc-subsection">
      <h4>What It Scans</h4>
      <p>Examines Windows Event Logs and system artifacts for security indicators:</p>
    </div>

    <div className="doc-artifact">
      <h5>1. Failed Login Attempts (Event ID 4625)</h5>
      <div className="artifact-details">
        <p><strong>What We Look For:</strong></p>
        <ul>
          <li>Failed logon attempts to local or domain accounts</li>
          <li>Source IP addresses of failed attempts</li>
          <li>Logon types (network, interactive, remote desktop)</li>
          <li>Failure reasons (bad password, account disabled, expired password)</li>
        </ul>
        <p><strong>Why It Matters:</strong></p>
        <ul>
          <li><strong>Brute Force Attacks:</strong> Multiple failed attempts from same IP indicates password guessing</li>
          <li><strong>Credential Stuffing:</strong> Automated login attempts with stolen credentials</li>
          <li><strong>Insider Activity:</strong> Failed attempts from internal users trying unauthorized access</li>
          <li><strong>Timeframe Evidence:</strong> Timestamps show when attack occurred</li>
        </ul>
        <div className="artifact-example">
          <strong>Example Scenario:</strong> 50 failed RDP login attempts from foreign IP in 5 minutes = likely attack
        </div>
      </div>
    </div>

    <div className="doc-artifact">
      <h5>2. Successful Logons (Event ID 4624)</h5>
      <div className="artifact-details">
        <p><strong>What We Look For:</strong></p>
        <ul>
          <li>Successful logon events with timestamps</li>
          <li>Logon type (network, interactive, RDP, service)</li>
          <li>Source IP addresses and workstation names</li>
          <li>Privileged account usage</li>
        </ul>
        <p><strong>Why It Matters:</strong></p>
        <ul>
          <li><strong>Unauthorized Access:</strong> Logons from unexpected IPs or unusual times</li>
          <li><strong>Lateral Movement:</strong> Network logons between systems during attack</li>
          <li><strong>Persistence:</strong> Service account logons may indicate malware</li>
          <li><strong>Timeline Verification:</strong> Confirms when attacker gained access</li>
          <li><strong>Privilege Escalation:</strong> Admin account logons following normal user access</li>
        </ul>
        <div className="artifact-example">
          <strong>Example Scenario:</strong> Admin account RDP logon at 3 AM from foreign country = compromise indicator
        </div>
      </div>
    </div>

    <div className="doc-artifact">
      <h5>3. Account Lockouts (Event ID 4740)</h5>
      <div className="artifact-details">
        <p><strong>What We Look For:</strong></p>
        <ul>
          <li>User accounts locked due to failed logon attempts</li>
          <li>Source computer that caused lockout</li>
          <li>Account names and lockout timestamps</li>
        </ul>
        <p><strong>Why It Matters:</strong></p>
        <ul>
          <li><strong>Attack Detection:</strong> Lockouts often indicate brute force attempts</li>
          <li><strong>Targeted Accounts:</strong> Shows which users are being targeted</li>
          <li><strong>Attack Sophistication:</strong> Distributed attacks may avoid lockouts</li>
          <li><strong>User Behavior:</strong> May indicate frustrated user or forgotten password</li>
        </ul>
      </div>
    </div>

    <div className="doc-artifact">
      <h5>4. Special Privilege Logons (Event ID 4672)</h5>
      <div className="artifact-details">
        <p><strong>What We Look For:</strong></p>
        <ul>
          <li>Logons with administrator or elevated privileges</li>
          <li>Specific privileges assigned (e.g., SeDebugPrivilege, SeBackupPrivilege)</li>
          <li>Service account privilege usage</li>
        </ul>
        <p><strong>Why It Matters:</strong></p>
        <ul>
          <li><strong>Privilege Escalation:</strong> Unauthorized elevation to admin rights</li>
          <li><strong>Dangerous Privileges:</strong> Debug/backup privileges allow system manipulation</li>
          <li><strong>Malware Activity:</strong> Malware often requires elevated privileges</li>
          <li><strong>Data Exfiltration:</strong> Backup privileges allow copying protected files</li>
        </ul>
      </div>
    </div>

    <div className="doc-artifact">
      <h5>5. New Process Creation (Event ID 4688)</h5>
      <div className="artifact-details">
        <p><strong>What We Look For:</strong></p>
        <ul>
          <li>Processes launched on the system</li>
          <li>Process names, paths, and command lines</li>
          <li>Parent process information</li>
          <li>User account that launched process</li>
        </ul>
        <p><strong>Why It Matters:</strong></p>
        <ul>
          <li><strong>Malware Execution:</strong> Suspicious executables or scripts</li>
          <li><strong>Hacking Tools:</strong> Mimikatz, PsExec, netcat, etc.</li>
          <li><strong>Reconnaissance:</strong> Network scanning tools or enumeration commands</li>
          <li><strong>Data Staging:</strong> Archive tools (WinRAR, 7zip) may indicate data collection</li>
          <li><strong>Lateral Movement:</strong> Remote execution tools</li>
        </ul>
        <div className="artifact-example">
          <strong>Example Scenario:</strong> Mimikatz.exe launched by web server account = credential theft
        </div>
      </div>
    </div>

    <div className="doc-artifact">
      <h5>6. Account Management Changes (Event IDs 4720, 4726, 4732)</h5>
      <div className="artifact-details">
        <p><strong>What We Look For:</strong></p>
        <ul>
          <li>User account creation or deletion (4720, 4726)</li>
          <li>Group membership changes (4732 - member added to group)</li>
          <li>Account attribute modifications</li>
          <li>Who made the changes and when</li>
        </ul>
        <p><strong>Why It Matters:</strong></p>
        <ul>
          <li><strong>Backdoor Accounts:</strong> Attackers create hidden admin accounts</li>
          <li><strong>Privilege Grants:</strong> Adding users to Admin/Domain Admin groups</li>
          <li><strong>Covering Tracks:</strong> Deleting accounts after attack</li>
          <li><strong>Insider Threats:</strong> Unauthorized privilege escalation</li>
        </ul>
      </div>
    </div>

    <div className="doc-artifact">
      <h5>7. Security Log Cleared (Event ID 1102)</h5>
      <div className="artifact-details">
        <p><strong>What We Look For:</strong></p>
        <ul>
          <li>Security event log clearing events</li>
          <li>User account that cleared logs</li>
          <li>Timestamp of log clearing</li>
        </ul>
        <p><strong>Why It Matters:</strong></p>
        <ul>
          <li><strong>Evidence Destruction:</strong> Attacker trying to hide their tracks</li>
          <li><strong>Highly Suspicious:</strong> Legitimate admins rarely clear security logs</li>
          <li><strong>Timeline Gap:</strong> Indicates period where activity is hidden</li>
          <li><strong>Consciousness of Guilt:</strong> Shows intent to conceal actions</li>
        </ul>
        <div className="artifact-example">
          <strong>⚠️ Critical Indicator:</strong> Security log cleared during incident timeframe = red flag
        </div>
      </div>
    </div>

    <div className="doc-subsection">
      <h4>How The Scanner Works</h4>
      <ol>
        <li><strong>Event Log Access:</strong> Reads Windows Security event logs (.evtx files)</li>
        <li><strong>Event Filtering:</strong> Focuses on security-relevant Event IDs</li>
        <li><strong>Pattern Detection:</strong> Identifies suspicious patterns (frequency, timing, source)</li>
        <li><strong>Correlation:</strong> Links related events together (e.g., failed attempts followed by success)</li>
        <li><strong>Risk Scoring:</strong> Categorizes findings by severity</li>
        <li><strong>Timeline Creation:</strong> Presents events in chronological order</li>
      </ol>
    </div>

    <div className="doc-subsection">
      <h4>Interpreting Results</h4>
      <div className="result-guidance">
        <p><strong>High-Risk Indicators:</strong></p>
        <ul>
          <li>Multiple failed logons from external IPs</li>
          <li>Successful logon after failed attempts (successful breach)</li>
          <li>Admin logons at unusual hours</li>
          <li>New account creation by non-IT staff</li>
          <li>Security log clearing</li>
          <li>Privilege escalation events</li>
          <li>Known hacking tools in process list</li>
        </ul>

        <p><strong>Medium-Risk Indicators:</strong></p>
        <ul>
          <li>Occasional failed logons (may be user error)</li>
          <li>Service account logons during maintenance windows</li>
          <li>Scheduled task execution</li>
          <li>Legitimate admin tool usage</li>
        </ul>

        <p><strong>Investigation Tips:</strong></p>
        <ul>
          <li>Look for <strong>clusters</strong> of events in short timeframes</li>
          <li>Correlate with <strong>network traffic</strong> if available</li>
          <li>Check for <strong>lateral movement</strong> (same account on multiple systems)</li>
          <li>Verify <strong>legitimate business need</strong> for elevated privileges</li>
          <li>Cross-reference with <strong>employee schedules</strong> and time zones</li>
        </ul>
      </div>
    </div>

    <div className="doc-subsection">
      <h4>Forensic Value</h4>
      <ul>
        <li><strong>Breach Detection:</strong> Identify unauthorized access attempts</li>
        <li><strong>Timeline Establishment:</strong> When did attack begin? How long did it last?</li>
        <li><strong>Attribution:</strong> Source IPs and account names</li>
        <li><strong>Scope Assessment:</strong> Which accounts and systems were compromised</li>
        <li><strong>Intent Evidence:</strong> Log clearing shows intentional concealment</li>
        <li><strong>Legal Evidence:</strong> Event logs are court-admissible and timestamped</li>
        <li><strong>Incident Response:</strong> Guides containment and remediation efforts</li>
      </ul>
    </div>

    <div className="doc-callout warning">
      <strong>⚠️ Important Notes:</strong>
      <ul>
        <li>Event log retention varies by system (typically 30-90 days)</li>
        <li>Attackers may clear or disable logging</li>
        <li>Requires Windows auditing to be enabled</li>
        <li>High volume of events requires analysis tools</li>
        <li>Consider centralized logging (SIEM) for network-wide view</li>
      </ul>
    </div>
  </div>
);
