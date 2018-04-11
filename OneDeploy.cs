using System;
using System.Diagnostics;
using System.Globalization;
using System.Collections.Generic;
using System.Text;
using System.Management;
using System.IO;
using System.Threading;

namespace ConsoleApplication1
{
    /// <summary>
    /// Main Class
    /// </summary>
    class Program
    {
        private string nasLogin = null;
        private string remoteLogin = "level0";
        //workstation, branch
        private Dictionary<string, string> workstationDict = new Dictionary<string, string>();
        //workstation, password
        private Dictionary<string, string> passwordDict = new Dictionary<string, string>();
        //workstation, bdm_initiated_flag (true)
        private Dictionary<string, string> bdmStatusDict = new Dictionary<string, string>();
        //potential password list
        private List<string> passwordList = new List<string>();
        public string getRemoteLogin()
        {
            return this.remoteLogin;
        }
        public void setLogin(string login)
        {
            Logger.logging("setLogin(): set NAS login to " + login);
            this.nasLogin = login;
        }
        public string getNasLogin()
        {
            return this.nasLogin;
        }
        public List<string> getPasswordList()
        {
            return this.passwordList;
        }
        public void setPasswordList()
        {
            this.passwordList.Add("aaa");
            this.passwordList.Add("bbb");
            this.passwordList.Add("ccc");
        }
        public Dictionary<string, string> getBdmStatusDict()
        {
            return this.bdmStatusDict;
        }
        public bool addToBdmStatusDict(string workstation, string status)
        {
            //valid status
            List<string> statusList = new List<string>();
            statusList.Add("initiated");
            statusList.Add("running");
            statusList.Add("stop");
            statusList.Add("unknown");

            //log if invalid status
            if (!statusList.Contains(status))
            {
                Logger.logging("addToBdmStatusDict(): invalid parameter status value " + status);
                return false;
            }

            //add bdm flag
            if (!this.bdmStatusDict.ContainsKey(workstation))
            {
                Logger.logging("addToBdmStatusDict(): set " + workstation + " status " + status);
                this.bdmStatusDict.Add(workstation, status);
            }
            else
            {
                //copy dict and update the "copied" dict otherwise a runtime error occur
                Dictionary<string, string> tmpDict = new Dictionary<string, string>(this.bdmStatusDict);

                //update status on the tmpDict
                if (!string.Equals(tmpDict[workstation], status))
                {
                    Logger.logging("addToBdmStatusDict(): update " + workstation + " status " + status);
                    tmpDict[workstation] = status;

                    //copy the status dict from tmp dict
                    this.bdmStatusDict = tmpDict;

                    return true;
                }
            }

            return true;
        }
        public void removeFromBdmStatusDict(string workstation)
        {
            //remove
            Dictionary<string, string> t = new Dictionary<string, string>();
            if (this.bdmStatusDict.ContainsKey(workstation))
            {
                Logger.logging("removeFromBdmStatusDict(): remove " + workstation + " from dictionary");
                this.bdmStatusDict.Remove(workstation);
            }
        }
        public Dictionary<string, string> getPasswordDict()
        {
            return this.passwordDict;
        }
        public void removeFromPasswordDict(string workstation)
        {
            //remove
            Dictionary<string, string> t = new Dictionary<string, string>();
            if (this.passwordDict.ContainsKey(workstation))
            {
                Logger.logging("removeFromPasswordDict(): remove " + workstation + " from dictionary");
                this.passwordDict.Remove(workstation);
            }
        }
        public void addToPasswordDict(string workstation)
        {
            string password = null;

            //return if passwordDict already contains key to save time with checking password
            //workstation can be removed and added back to queue to check password again
            if (this.passwordDict.ContainsKey(workstation))
            {
                Logger.logging("addToPasswordDict(): " + workstation + " already in password dictionary");
                return;
            }

            int count = 1;

            //find the correct password
            foreach (string pass in this.passwordList)
            {
                //Console.WriteLine("Verify password " + pass + " for workstation " + workstation);
                Logger.logging("addToPasswordDict9): verify password " + getPasswordLast2Char(pass) + " [" + count + "/" + this.passwordList.Count + "]");
                if (isPasswordCorrect(workstation, workstation, getRemoteLogin(), pass))
                {
                    //Console.WriteLine("Found password " + pass + " for " + workstation);
                    //keyToContinue();
                    password = pass;
                    break;
                }
                count++;
            }

            //log password
            if (string.IsNullOrEmpty(password))
            {
                Logger.logging("addToPasswordDict(): unable to validate " + workstation + " password");
            }
            else
            {
                Logger.logging("addToPasswordDict(): " + workstation + " password validated");
            }
            

            //add password
            if (!this.passwordDict.ContainsKey(workstation))
            {
                Logger.logging("addToPasswordDict(): add " + workstation + " to password dictionary");
                this.passwordDict.Add(workstation, password);
            }
            else
            {
                //update password
                Logger.logging("addToPasswordDict(): update " + workstation + " in password dictionary");
                this.passwordDict[workstation] = password;
            }
        }
        public Dictionary<string, string> getWorkstationDict()
        {
            return this.workstationDict;
        }
        public void removeFromWorkstationDict(string workstation)
        {
            //remove
            Dictionary<string, string> t = new Dictionary<string, string>();
            if (this.workstationDict.ContainsKey(workstation))
            {
                Logger.logging("removeFromWorkstationDict(): remove " + workstation + " from dictionary");
                this.workstationDict.Remove(workstation);
            }
        }
        public bool addToWorkstationDict(string workstation, string branch)
        {
            if (!this.workstationDict.ContainsKey(workstation))
            {
                this.workstationDict.Add(workstation, branch);
                return true;
            }
            else
            {
                return false;
            }
        }
        public void clearWorkstationDict()
        {
            this.workstationDict.Clear();
        }
        public string getBranch(string workstation)
        {
            if (this.workstationDict.ContainsKey(workstation))
            {
                return this.workstationDict[workstation];
            }
            else
            {
                return null;
            }
        }

        //main program
        static void Main(String[] args)
        {
            Logger.logging("=================================================================");
            Console.Clear();
            Program p = new Program();
            string input = null;

            //initialize password list
            p.setPasswordList();

            while (true)
            {
                displayOneDeployPrompt(p);
                input = Console.ReadLine();
                processInput(input, p);
            }
        }
        /// <summary>
        /// Return true if password is correct
        /// </summary>
        /// <param name="sPrinterName"></param>
        public static bool isPasswordCorrect(String workstation, String domain, String username, String password)
        {

            //Console.WriteLine("isPasswordCorrect(): " + workstation + " : " + domain + " : " + username + " : " + password);
            bool correctPassword = true;

            //create ConnectionOptions object
            ConnectionOptions connOptions = new ConnectionOptions();
            //connOptions.Impersonation = ImpersonationLevel.Impersonate;

            //use username if available
            if (!String.IsNullOrEmpty(username))
            {
                connOptions.Username = domain + "\\" + username;
                connOptions.Password = password;
            }
            //else impersonate (default)

            //connOptions.EnablePrivileges = true;

            //create and connect ManagementScope object
            ManagementScope manScope = new ManagementScope(String.Format(@"\\{0}\ROOT\CIMV2", workstation), connOptions);

            try
            {
                manScope.Connect();
            }
            catch (UnauthorizedAccessException e)
            {
                //console.WriteLine("isPasswordCorrect() Exception: " + e.Message);
                Logger.logging("isPasswordCorrect() Exception: " + e.Message);
                correctPassword = false;
            }
            catch (Exception e)
            {
                //Console.WriteLine("isPasswordCorrect() Exception: " + e.Message);
                Logger.logging("isPasswordCorrect() Exception: " + e.Message);
                correctPassword = false;
            }

            return correctPassword;
        }
        /// <summary>
        /// Display root@OneDeploy prompt
        /// </summary>
        /// <param name="p"></param>
        public static void displayOneDeployPrompt(Program p)
        {
            string login = null;
            login = p.getNasLogin();

            Console.Write("root@OneDeploy# ");
        }
        /// <summary>
        /// Process user input
        /// </summary>
        /// <param name="input"></param>
        public static void processInput(string input, Program p)
        {
            string workstation = null;
            string branch = null;

            try
            {
                if (input.Equals("help", StringComparison.OrdinalIgnoreCase))
                {
                    displayHelp();
                }
                else if (input.Equals("kickoff", StringComparison.OrdinalIgnoreCase))
                {
                    Logger.logging("processInput(): kickoff");

                    //accept user input to commit "all" or "new"
                    string commit = null;

                    Console.Clear();

                    //clear workstation dictionary
                    //p.clearWorkstationDict();

                    //prompt umtil get valid login (no space or null)
                    while (true)
                    {
                        Console.Clear();
                        Console.WriteLine("Current NAS login: " + p.getNasLogin());

                        //allow user to change NAS login
                        string loginName = getLoginInput();

                        //invalid current login
                        if (string.IsNullOrEmpty(p.getNasLogin()))
                        {
                            //invalid new login
                            if (isNullOrWhiteSpace(loginName))
                            {
                                printNewLine();
                                Console.WriteLine("Invalid login");
                                printNewLine();
                                keyToContinue();
                                continue;
                            }
                            else
                            {
                                //set and break if valid new login
                                p.setLogin(loginName);
                                break;
                            }
                        }
                        else //valid current login
                        {
                            //break if new login name is empty (no change)
                            if (string.IsNullOrEmpty(loginName))
                            {
                                break;
                            }
                            else if (isNullOrWhiteSpace(loginName))
                            {
                                //invalid new login
                                printNewLine();
                                Console.WriteLine("Invalid login");
                                printNewLine();
                                keyToContinue();
                                continue;
                            }
                            else
                            {
                                //set and break if valid new login
                                p.setLogin(loginName);
                                break;
                            }
                        }
                    }

                    //get workstation input
                    while (true)
                    {
                        Console.Clear();
                        Console.WriteLine("NAS login: " + p.getNasLogin());
                        printNewLine();
                        
                        //print workstation entered so far
                        if (p.getWorkstationDict().Count > 0)
                        {
                            foreach (KeyValuePair<string, string> wksDict in p.getWorkstationDict())
                            {
                                if (p.getBdmStatusDict().ContainsKey(wksDict.Key))
                                {
                                    Console.WriteLine(wksDict.Key + " " + p.getBdmStatusDict()[wksDict.Key]);
                                }
                                else
                                {
                                    //password is null -> unable to validate login
                                    if (p.getPasswordDict().ContainsKey(wksDict.Key) &&
                                        string.IsNullOrEmpty(p.getPasswordDict()[wksDict.Key]))
                                    {
                                        Console.WriteLine(wksDict.Key + " unreacheable");
                                    }
                                    else if (p.getPasswordDict().ContainsKey(wksDict.Key) &&
                                        !string.IsNullOrEmpty(p.getPasswordDict()[wksDict.Key]))
                                    {
                                        Console.WriteLine(wksDict.Key + " login validated");
                                    }
                                    else
                                    {
                                        Console.WriteLine(wksDict.Key);
                                    }
                                }
                            }
                            printNewLine();
                        }
                        Console.Write("Enter workstation name or commit when done: ");
                        workstation = Console.ReadLine();

                        //add workstation and branch to dictionary
                        if (isWorkstationNameValid(workstation, ref branch))
                        {
                            if (p.getWorkstationDict().ContainsKey(workstation))
                            {
                                printNewLine();
                                Console.WriteLine("Workstation already in queue");
                                printNewLine();
                                keyToContinue();
                            }
                            else if (p.getWorkstationDict().ContainsValue(branch))
                            {
                                printNewLine();
                                Console.WriteLine("Another workstation from same branch already in queue");
                                printNewLine();
                                keyToContinue();
                            }
                            else
                            {
                                Logger.logging("processInput(): adding " + workstation + " to queue"); 
                                p.addToWorkstationDict(workstation, branch);

                                //validate password only if it's not in password dictionary
                                if (!p.getPasswordDict().ContainsKey(workstation))
                                {
                                    printNewLine();
                                    Console.Write("Validate login for " + workstation);
                                    p.addToPasswordDict(workstation);
                                }
                            }
                        }
                        else if (string.Equals("commit", workstation))
                        {
                            //prompt user to select new or all if there are both new and initiated workstations
                            if (((p.getWorkstationDict().Count - p.getBdmStatusDict().Count) > 0) &&
                                (p.getBdmStatusDict().Count > 0))
                            {
                                while (true)
                                {
                                    printNewLine();
                                    Console.Write("Commit all or new: ");
                                    commit = Console.ReadLine();
                                    //check input is "all" or "new"
                                    if (string.Equals(commit, "all") || string.Equals(commit, "new"))
                                    {
                                        //kickoff workstations here
                                        if (p.getWorkstationDict().Count > 0)
                                        {
                                            //kick off "new" workstations
                                            if (string.Equals(commit, "new"))
                                            {
                                                //if total > initiated, then there are new workstations
                                                if (p.getWorkstationDict().Count > p.getBdmStatusDict().Count)
                                                {
                                                    Logger.logging("processInput(): kickoff " + (p.getWorkstationDict().Count - p.getBdmStatusDict().Count) +
                                                                    " new workstations");
                                                    printNewLine();
                                                    Console.WriteLine("Total new workstations kickoff: " + (p.getWorkstationDict().Count - p.getBdmStatusDict().Count));
                                                    foreach (KeyValuePair<string, string> wksDict in p.getWorkstationDict())
                                                    {
                                                        //initiate bdm if it's not in the initiated dictionary
                                                        if (!p.getBdmStatusDict().ContainsKey(wksDict.Key))
                                                        {
                                                            printNewLine();
                                                            Console.WriteLine("Kickoff workstation [" + wksDict.Key + "] for branch [" + wksDict.Value + "]");
                                                            kickoffBdm(wksDict.Key, p);
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    //no new workstations
                                                    printNewLine();
                                                    Logger.logging("processInput(): there are no new workstations to kickoff");
                                                    Console.WriteLine("There are no new workstations to kickoff");
                                                }
                                            }
                                            else
                                            {
                                                //kickoff "all" workstations
                                                Logger.logging("processInput(): kickoff all " + p.getWorkstationDict().Count + " workstations");
                                                printNewLine();
                                                Console.WriteLine("Total workstations kickoff: " + p.getWorkstationDict().Count);
                                                foreach (KeyValuePair<string, string> wksDict in p.getWorkstationDict())
                                                {
                                                    printNewLine();
                                                    Console.WriteLine("Kickoff workstation [" + wksDict.Key + "] for branch [" + wksDict.Value + "]");
                                                    kickoffBdm(wksDict.Key, p);
                                                }
                                            }
                                        }
                                        else
                                        {
                                            //no workstations
                                            printNewLine();
                                            Logger.logging("processInput(): there are no workstations to kickoff");
                                            Console.WriteLine("There are no workstations to kickoff");
                                        }
                                    }
                                    else
                                    {
                                        printNewLine();
                                        Console.WriteLine("Invalid input");
                                    }
                                    break;
                                }
                            }
                            else
                            {
                                //kickoff "all" workstations
                                if (p.getWorkstationDict().Count > 0)
                                {
                                    Logger.logging("processInput(): kickoff all " + p.getWorkstationDict().Count + " workstations");
                                    printNewLine();
                                    Console.WriteLine("Total workstations kickoff: " + p.getWorkstationDict().Count);
                                    foreach (KeyValuePair<string, string> wksDict in p.getWorkstationDict())
                                    {
                                        printNewLine();
                                        Console.WriteLine("Kickoff workstation [" + wksDict.Key + "] for branch [" + wksDict.Value + "]");
                                        kickoffBdm(wksDict.Key, p);
                                    }
                                }
                                else
                                {
                                    //no workstations
                                    printNewLine();
                                    Logger.logging("processInput(): there are no workstations to kickoff");
                                    Console.WriteLine("There are no workstations to kickoff");
                                }
                            }
                            printNewLine();
                            keyToContinue();
                            continue;
                        }
                        else if (string.Equals("kill", workstation))
                        {
                            printNewLine();
                            Console.Write("Enter workstation name: ");
                            workstation = Console.ReadLine();

                            //add workstation and branch to dictionary
                            if (isWorkstationNameValid(workstation, ref branch))
                            {
                                if (p.getWorkstationDict().ContainsKey(workstation) && p.getPasswordDict().ContainsKey(workstation) &&
                                    !string.IsNullOrEmpty(p.getPasswordDict()[workstation]))
                                {

                                    string pid = SystemProcess.getBdmProcessId(workstation, workstation, p.getRemoteLogin(), p.getPasswordDict()[workstation]);
                                    //get the pid for bdm
                                    if (!string.Equals(pid, "-1"))
                                    {
                                        if (SystemProcess.killProcess(workstation, workstation, p.getRemoteLogin(),
                                            p.getPasswordDict()[workstation], pid) == true)
                                        {
                                            printNewLine();
                                            Console.WriteLine("Successfully kill bdm on " + workstation);
                                        }
                                        else
                                        {
                                            printNewLine();
                                            Console.WriteLine("Failed to kill bdm on " + workstation);
                                        }
                                    }
                                    else
                                    {
                                        printNewLine();
                                        Console.WriteLine("Bdm is not running on " + workstation);
                                    }
                                    printNewLine();
                                    keyToContinue();
                                }
                                else
                                {
                                    printNewLine();
                                    Console.WriteLine("Workstation is not in queue or it's unreacheable");
                                    printNewLine();
                                }
                            }

                        }
                        else if (string.Equals("load", workstation))
                        {
                            printNewLine();
                            Console.Write("Enter filename: ");
                            string fileName = Console.ReadLine();
                            if (!File.Exists(fileName))
                            {
                                printNewLine();
                                Console.WriteLine("Invalid filename or file not exist");
                                keyToContinue();
                            }
                            else
                            {
                                StreamReader sr = new StreamReader(fileName);
                                while ((workstation = sr.ReadLine()) != null)
                                {
                                    //add workstation and branch to dictionary
                                    if (isWorkstationNameValid(workstation, ref branch))
                                    {
                                        if (p.getWorkstationDict().ContainsKey(workstation))
                                        {
                                            printNewLine();
                                            Console.WriteLine(workstation + " already in queue");
                                        }
                                        else if (p.getWorkstationDict().ContainsValue(branch))
                                        {
                                            printNewLine();
                                            Console.WriteLine(workstation + " another workstation from same branch already in queue");
                                        }
                                        else
                                        {
                                            Logger.logging("processInput(): add " + workstation + " to queue");
                                            printNewLine();
                                            Console.WriteLine("Add workstation " + workstation + " to queue");
                                            p.addToWorkstationDict(workstation, branch);

                                            //validate password only if it's not in password dictionary
                                            if (!p.getPasswordDict().ContainsKey(workstation))
                                            {
                                                Console.WriteLine("Validate login for " + workstation);
                                                p.addToPasswordDict(workstation);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        printNewLine();
                                        Console.WriteLine(workstation + " invalid workstation name");
                                    }
                                }
                                printNewLine();
                                keyToContinue();
                            }
                        }
                        else if (string.Equals("refresh", workstation))
                        {
                            if (p.getBdmStatusDict().Count > 0)
                            {
                                foreach (KeyValuePair<string, string> w in p.getBdmStatusDict())
                                {
                                    printNewLine();
                                    Console.WriteLine("Checking status for " + w.Key);
                                    try
                                    {
                                        if (SystemProcess.isBdmProcessExist(w.Key, w.Key, p.getRemoteLogin(), p.getPasswordDict()[w.Key]))
                                        {
                                            //update status to running
                                            p.addToBdmStatusDict(w.Key, "running");
                                            Console.WriteLine("bdm is running");
                                        }
                                        else
                                        {
                                            p.addToBdmStatusDict(w.Key, "stop");
                                            Console.WriteLine("bdm stop running");
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        Console.WriteLine(e.Message);
                                        p.addToBdmStatusDict(w.Key, "unknown");
                                        Console.WriteLine("bdm unknown");
                                    }
                                }
                                printNewLine();
                                keyToContinue();
                            }
                            else
                            {
                                printNewLine();
                                Console.WriteLine("There are no active workstations");
                                printNewLine();
                                keyToContinue();
                            }
                        }
                        else if (string.Equals("reset", workstation))
                        {
                            //reset the current password
                            if (p.getWorkstationDict().Count > 0)
                            {
                                foreach (KeyValuePair<string, string> wksDict in p.getWorkstationDict())
                                {
                                    printNewLine();
                                    Console.WriteLine("Re-validate password for " + wksDict.Key);
                                    p.removeFromPasswordDict(wksDict.Key);
                                    p.addToPasswordDict(wksDict.Key);
                                }

                                if (p.getBdmStatusDict().Count > 0)
                                {
                                    foreach (KeyValuePair<string, string> w in p.getBdmStatusDict())
                                    {
                                        printNewLine();
                                        Console.WriteLine("Checking status for " + w.Key);
                                        try
                                        {
                                            if (SystemProcess.isBdmProcessExist(w.Key, w.Key, p.getRemoteLogin(), p.getPasswordDict()[w.Key]))
                                            {
                                                //update status to running
                                                p.addToBdmStatusDict(w.Key, "running");
                                                Console.WriteLine("bdm is running");
                                            }
                                            else
                                            {
                                                p.addToBdmStatusDict(w.Key, "stop");
                                                Console.WriteLine("bdm stop running");
                                            }
                                        }
                                        catch (Exception e)
                                        {
                                            Console.WriteLine(e.Message);
                                            p.addToBdmStatusDict(w.Key, "unknown");
                                            Console.WriteLine("bdm unknown");
                                        }
                                    }
                                    printNewLine();
                                    keyToContinue();
                                }
                                else
                                {
                                    printNewLine();
                                    Console.WriteLine("There are no active workstations");
                                    printNewLine();
                                    keyToContinue();
                                }
                            }
                        }
                        else if (string.Equals("help", workstation))
                        {
                            displayKickoffHelp();
                        }
                        else if (string.Equals("quit", workstation))
                        {
                            return;
                        }
                        else if (string.Equals("remove", workstation))
                        {
                            printNewLine();
                            Console.Write("Enter workstation to remove: ");
                            string wks = Console.ReadLine();
                            if (p.getWorkstationDict().ContainsKey(wks))
                            {
                                p.removeFromWorkstationDict(wks);
                                p.removeFromBdmStatusDict(wks);
                                p.removeFromPasswordDict(wks);
                            }
                            else
                            {
                                printNewLine();
                                Console.WriteLine("This workstation is not in the queue");
                                printNewLine();
                                keyToContinue();
                            }
                        }
                        else
                        {
                            printNewLine();
                            Console.WriteLine("Invalid workstation");
                            printNewLine();
                            keyToContinue();
                        }
                    }
                }
                else if (input.Equals("copy", StringComparison.OrdinalIgnoreCase))
                {
                    List<string> wksList = new List<string>();
                    while (true)
                    {
                        Console.Clear();
                        Console.WriteLine("NAS login: " + p.getNasLogin());

                        if (wksList.Count > 0)
                        {
                            printNewLine();
                            foreach (string w in wksList)
                            {
                                Console.WriteLine(w);
                            }
                        }

                        printNewLine();
                        Console.Write("Enter workstation name or commit when done: ");
                        workstation = Console.ReadLine();

                        //add workstation to list
                        if (isWorkstationNameValid(workstation, ref branch))
                        {
                            if (wksList.Contains(workstation))
                            {
                                printNewLine();
                                Console.WriteLine("Workstation already in queue");
                                printNewLine();
                                keyToContinue();
                            }
                            else
                            {
                                wksList.Add(workstation);

                                //validate password if it's not in password dictionary
                                if (!p.getPasswordDict().ContainsKey(workstation))
                                {
                                    printNewLine();
                                    Console.Write("Validate login for " + workstation);
                                    p.addToPasswordDict(workstation);
                                }
                            }
                        }
                        else if (string.Equals("commit", workstation))
                        {
                            //copy package to each worktation in temp list
                            foreach (string w in wksList)
                            {
                                printNewLine();
                                Console.WriteLine("Copy to " + w);
                                copyPackage(w, p);
                            }
                            printNewLine();
                            keyToContinue();
                        }
                        else if (string.Equals("clear", workstation))
                        {
                            //clear the workstation temp list
                            wksList.Clear();
                        }
                        else if (string.Equals("help", workstation))
                        {
                            displayCopyHelp();
                        }
                        else if (string.Equals("quit", workstation))
                        {
                            break;
                        }
                        else
                        {
                            printNewLine();
                            Console.WriteLine("Invalid input");
                            printNewLine();
                            keyToContinue();
                        }
                    }
                }
                else if (input.Equals("download", StringComparison.OrdinalIgnoreCase))
                {
                    while (true)
                    {
                        Console.Clear();
                        Console.WriteLine("NAS login: " + p.getNasLogin());

                        //print workstation entered so far
                        if (p.getWorkstationDict().Count > 0)
                        {
                            printNewLine();

                            foreach (KeyValuePair<string, string> wksDict in p.getWorkstationDict())
                            {
                                if (p.getBdmStatusDict().ContainsKey(wksDict.Key))
                                {
                                    Console.WriteLine(wksDict.Key + " " + p.getBdmStatusDict()[wksDict.Key]);
                                }
                                else
                                {
                                    //password is null -> bad login or workstation unreacheable
                                    if (p.getPasswordDict().ContainsKey(wksDict.Key) &&
                                        string.IsNullOrEmpty(p.getPasswordDict()[wksDict.Key]))
                                    {
                                        Console.WriteLine(wksDict.Key + ": unreachables");
                                    }
                                    else if (p.getPasswordDict().ContainsKey(wksDict.Key) &&
                                        !string.IsNullOrEmpty(p.getPasswordDict()[wksDict.Key]))
                                    {
                                        Console.WriteLine(wksDict.Key + ": login validated");
                                    }
                                    else
                                    {
                                        Console.WriteLine(wksDict.Key);
                                    }
                                }
                            }
                        }
                        printNewLine();
                        Console.Write("Enter a workstation name or all to download log: ");
                        workstation = Console.ReadLine();

                        //add workstation to password dict and call downloadLog()
                        if (isWorkstationNameValid(workstation, ref branch))
                        {
                            if (!p.getPasswordDict().ContainsKey(workstation))
                            {
                                printNewLine();
                                Console.Write("Validate login for " + workstation);
                                p.addToPasswordDict(workstation);
                            }

                            //download log
                            downloadLog(p, workstation);
                        }
                        else if (string.Equals(workstation, "all"))
                        {
                            downloadLog(p, "all");
                        }
                        else if (string.Equals("refresh", workstation))
                        {
                            if (p.getBdmStatusDict().Count > 0)
                            {
                                foreach (KeyValuePair<string, string> w in p.getBdmStatusDict())
                                {
                                    printNewLine();
                                    Console.WriteLine("Checking status for " + w.Key);
                                    try
                                    {
                                        if (SystemProcess.isBdmProcessExist(w.Key, w.Key, p.getRemoteLogin(), p.getPasswordDict()[w.Key]))
                                        {
                                            //update status to running
                                            p.addToBdmStatusDict(w.Key, "running");
                                            Console.WriteLine("bdm is running");
                                        }
                                        else
                                        {
                                            p.addToBdmStatusDict(w.Key, "stop");
                                            Console.WriteLine("bdm stop running");
                                        }
                                    } catch (Exception e)
                                    {
                                        Console.WriteLine("processInput() Exception: " + e.Message);
                                        p.addToBdmStatusDict(w.Key, "unknown");
                                        Console.WriteLine("bdm unknown");
                                    }
                                }
                                printNewLine();
                                keyToContinue();
                            }
                            else
                            {
                                printNewLine();
                                Console.WriteLine("There are no active workstations");
                                printNewLine();
                                keyToContinue();
                            }
                        }
                        else if (string.Equals(workstation, "quit"))
                        {
                            break;
                        }
                        else
                        {
                            printNewLine();
                            Console.WriteLine("Invalid input");
                            printNewLine();
                            keyToContinue();
                        }
                    }
                }
                else if (input.Equals("clear", StringComparison.OrdinalIgnoreCase))
                {
                    Console.Clear();
                }
                else if (input.Equals("quit", StringComparison.OrdinalIgnoreCase))
                {
                    System.Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("Command not recognize. See help.");
                }
            }
            catch (Exception e)
            {
                Logger.logging("processInput() Exception: " + e.Message);
                Console.WriteLine("processInput() Exception: " + e.Message);
            }
        }
        /// <summary>
        /// Copy log to local Download directory
        /// </summary>
        public static void copyLog(Program p, string workstation)
        {
            string localDownloadFolder = "Download";
            string user = p.getRemoteLogin();
            string pass = p.getPasswordDict()[workstation];
            string adminShare = "admin$";
            string batFileName = "bdm.bat";
            string logName = "datamigr_" + workstation + ".log";
            string remoteLog = @"\\" + workstation + "\\" + adminShare + "\\" + logName;

            //return if password is null/invalid
            if (string.IsNullOrEmpty(workstation) || string.IsNullOrEmpty(pass))
            {
                Console.WriteLine("Workstation " + workstation + " unreacheable or null");
                return;
            }

            List<string> status = new List<string>();

            // mount admin share via net use
            if (NetUse.connectShare(workstation, workstation, user, pass, "admin$", ref status))
            {
                //Console.WriteLine("Able to connect: " + status[1].Trim());
                Logger.logging("downloadLog(): successfully connected to remote workstation");
                Console.WriteLine("Successfully connected to remote workstation");

                // create full path for bat file
                batFileName = @"\\" + workstation + "\\" + adminShare + "\\" + batFileName;

                // delete remote bat file
                if (File.Exists(batFileName))
                {
                    try
                    {
                        File.Delete(batFileName);
                    }
                    catch (Exception e)
                    {
                        Logger.logging("downloadLog() Exception: " + e.Message);
                        Console.WriteLine("downloadLog() Exception: " + e.Message);
                    }
                }

                try
                {
                    // append command to bat file                
                    StreamWriter sw_append = new StreamWriter(batFileName, true);
                    sw_append.WriteLine("%systemroot%\\system32\\xcopy /f /y c:\\temp\\bdm\\datamigr_%computername%.log %systemroot%");
                    sw_append.Close();
                }
                catch (Exception e)
                {
                    Logger.logging("downloadLog() Exception: " + e.Message);
                    Console.WriteLine("downloadLog() Exception: " + e.Message);
                }

                // kicks off remote bat file to copy log from c:\temp\bdm to %systemroot%
                try
                {
                    //create ConnectionOptions
                    ConnectionOptions connOptions = new ConnectionOptions();
                    connOptions.Username = user + "\\" + user;
                    connOptions.Password = pass;
                    connOptions.EnablePrivileges = true;

                    //create and connect ManagementScope object
                    ManagementScope manScope = new ManagementScope(String.Format(@"\\{0}\ROOT\CIMV2", workstation), connOptions);
                    manScope.Connect();

                    //create ObjectGetOptions object
                    ObjectGetOptions objectGetOptions = new ObjectGetOptions();

                    //create ManagementPath object new  process
                    ManagementPath managementPath = new ManagementPath("Win32_Process");

                    //hook up everything to the ManagementClass
                    ManagementClass processClass = new ManagementClass(manScope, managementPath, objectGetOptions);

                    ManagementBaseObject inParams = processClass.GetMethodParameters("Create");

                    //prepare command string
                    String command = batFileName;
                    inParams["CommandLine"] = command;

                    //calling invokemethod
                    //Console.WriteLine("Copy remote log to share");

                    ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);
                    //Console.WriteLine("Creation of the process returned: " + outParams["returnValue"]);

                    string pid = Convert.ToString(outParams["processId"]);

                    //wait for process to finish copying from c:\temp\bdm\*.log to %systemroot%
                    while (true)
                    {
                        if (SystemProcess.isProcessExist(workstation, workstation, user, pass, pid))
                        {
                            //Console.WriteLine("Copy in progress");
                            //sleeping for 10 secs
                            Thread.Sleep(10000);
                            continue;
                        }
                        else
                        {
                            //Console.WriteLine("Copy has completed");
                            break;
                        }
                    }

                }
                catch (Exception e)
                {
                    Logger.logging("copyLog() Exception: " + e.Message);
                    Console.WriteLine("copyLog() Exception: " + e.Message);
                }

                //copy remote log to local
                if (File.Exists(remoteLog))
                {
                    //mkdir local Download folder if not exists
                    try
                    {
                        if (!Directory.Exists(localDownloadFolder))
                        {
                            Directory.CreateDirectory(localDownloadFolder);
                        }
                    }
                    catch (Exception e)
                    {
                        printNewLine();
                        Logger.logging("copyLog() Exception: " + e.Message);
                        Console.WriteLine("copyLog() Exception: " + e.Message);
                    }

                    try
                    {
                        //copy log to Download folder if it exists
                        if (Directory.Exists(localDownloadFolder))
                        {
                            Console.WriteLine("Copy remote log to " + localDownloadFolder + " folder");
                            Logger.logging("copyLog(): copy remote log to " + localDownloadFolder + " folder");
                            File.Copy(remoteLog, localDownloadFolder + "\\" + logName, true);
                        }
                        else
                        {
                            //or copy to working directory of application
                            Console.WriteLine("Copy remote log to current directory");
                            Logger.logging("copyLog(): copy remote log to current directory");
                            File.Copy(remoteLog, Directory.GetCurrentDirectory() + "\\" + logName, true);
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.logging("copyLog() Exception: " + e.Message);
                        Console.WriteLine("copyLog() Exception: " + e.Message);
                    }


                    //disconnect share
                    List<string> status2 = new List<string>();
                    if (NetUse.disconnectShare(workstation, workstation, user, pass, adminShare, ref status2))
                    {
                        Logger.logging("copyLog(): successfully disconnected from remote workstation");
                        Console.WriteLine("Successfully disconnected from remote workstation");
                    }
                    else
                    {
                        Logger.logging("copyLog(): failed to disconnect from remote workstation: \"" + status2[2].Trim() + "\"");
                        Console.WriteLine("Failed to disconnect from remote workstation: \"" + status2[2].Trim() + "\"");
                    }
                }
                else
                {
                    Logger.logging("copyLog(): remote log not available for download");
                    Console.WriteLine("Remote log not available for download");
                }
            }
            else
            {
                if (status[2].IndexOf("1326", StringComparison.CurrentCultureIgnoreCase) >= 0)
                {
                    Logger.logging("copyLog(): remote connection failed: Invalid username and/or password");
                    Console.WriteLine("Remote connection failed: Invalid username and/or password");
                }
                else
                {
                    Logger.logging("copyLog(): Remote connection failed: \"" + status[2].Trim() + "\"");
                    Console.WriteLine("Remote connection failed: \"" + status[2].Trim() + "\"");
                }
            }


        }
        /// <summary>
        /// Get workstation log or all workstation log if argument equals all
        /// </summary>
        /// <param name="p"></param>
        /// <param name="workstation"></param>
        public static void downloadLog(Program p, string workstation)
        {
            string pass = null;

            // if workstation equals all then get all workstation log
            if (string.Equals(workstation, "all"))
            {
                if (p.getWorkstationDict().Count > 0)
                {
                    Logger.logging("downloadLog(): download log for all " + p.getWorkstationDict().Count + " workstations");
                    foreach (KeyValuePair<string, string> w in p.getWorkstationDict())
                    {
                        pass = p.getPasswordDict()[w.Key];

                        //copy log
                        if (!string.IsNullOrEmpty(pass))
                        {
                            printNewLine();
                            Console.WriteLine("Get log for " + w.Key);
                            Logger.logging("downloadLog(): download log for " + w.Key);
                            copyLog(p, w.Key);
                        }
                        else
                        {
                            //return if password is null/invalid
                            printNewLine();
                            Console.WriteLine(w.Key + " unreacheable");
                            Logger.logging("downloadLog(): " + w.Key + " unreacheable. Unable to download log");
                        }
                    }
                }
                else
                {
                    printNewLine();
                    Console.WriteLine("Workstation list empty");
                    Logger.logging("downloadLog(): workstation list empty");
                    printNewLine();
                    keyToContinue();
                }
            }
            else
            {
                //get log for single workstation
                pass = p.getPasswordDict()[workstation];
                if (!string.IsNullOrEmpty(pass))
                {
                    //copy log
                    printNewLine();
                    Console.WriteLine("Get log for " + workstation);
                    Logger.logging("downloadLog(): download log for " + workstation);
                    copyLog(p, workstation);
                }
                else
                {
                    printNewLine();
                    Console.WriteLine(workstation + " unreacheable");
                    Logger.logging("downloadLog(): " + workstation + " unreacheable. Unable to download log");
                    printNewLine();
                }
            }
            printNewLine();
            keyToContinue();
        }
        /// <summary>
        /// Copy BdmPkg.exe and bm.csv to remote machine but don't extract
        /// </summary>
        /// <param name="workstation"></param>
        /// <param name="p"></param>
        public static void copyPackage(string workstation, Program p)
        {
            string user = p.getRemoteLogin();
            string pass = p.getPasswordDict()[workstation];
            string adminShare = "admin$";
            //string batFileName = "bdm.bat";
            string bmFile = "bm.csv";
            string bdmPkg = "BdmPkg.exe";
            //use xcopy instead
            //string copyBmExe = "CopyBm.exe";

            //return if password is null/invalid
            if (string.IsNullOrEmpty(pass))
            {
                Logger.logging("kickoffBdm(): " + workstation + " unreacheable");
                Console.WriteLine("Skip " + workstation + " unreacheable");
                return;
            }

            // create Dictionary of file to delete/copy to remote
            // key = local file name
            // value = remote file name with path
            Dictionary<string, string> fileDict = new Dictionary<string, string>();
            //fileDict.Add(batFileName, @"\\" + workstation + "\\" + adminShare + "\\" + batFileName);
            fileDict.Add(bmFile, @"\\" + workstation + "\\" + adminShare + "\\" + bmFile);
            //use xcopy instead
            //fileDict.Add(copyBmExe, @"\\" + workstation + "\\" + adminShare + "\\" + copyBmExe);
            fileDict.Add(bdmPkg, @"\\" + workstation + "\\" + adminShare + "\\" + bdmPkg);

            List<string> status = new List<string>();

            // mount admin share via net use
            if (NetUse.connectShare(workstation, workstation, user, pass, "admin$", ref status))
            {
                //Console.WriteLine("Able to connect: " + status[1].Trim());
                Console.WriteLine("Successfully connected to remote workstation");

                //delete/copy file to remote
                foreach (KeyValuePair<string, string> file in fileDict)
                {                    
                    // copy bm.csv, CopyBm.exe, BdmPkg.exe to remote
                    /*
                    if (File.Exists(file.Key) && File.Exists(file.Value) &&
                        File.GetCreationTime(file.Key).Equals(File.GetCreationTime(file.Value)))
                    {
                        Console.WriteLine(file.Key + " is latest so update not required");
                    }
                    else if (!File.Exists(file.Key))
                    {
                        Console.WriteLine("Local file " + file.Key + " is missing!");
                    }
                    else
                    {
                        Console.WriteLine("Update remote file " + file.Key);
                        try
                        {
                            File.Copy(file.Key, file.Value, true);
                            File.SetCreationTime(file.Value, File.GetCreationTime(file.Key));
                        }
                        catch (Exception e)
                        {
                            Logger.logging("copyPackage() Exception: " + e.Message);
                            Console.WriteLine("copyPackage() Exception: " + e.Message);
                        }
                    }                    
                     */
                    //just copy
                    Console.WriteLine("Update remote file " + file.Key);
                    try
                    {
                        File.Copy(file.Key, file.Value, true);
                        File.SetCreationTime(file.Value, File.GetCreationTime(file.Key));
                    }
                    catch (Exception e)
                    {
                        Logger.logging("copyPackage() Exception: " + e.Message);
                        Console.WriteLine("copyPackage() Exception: " + e.Message);
                    }
                }

                //disconnect share
                List<string> status2 = new List<string>();
                if (NetUse.disconnectShare(workstation, workstation, user, pass, adminShare, ref status2))
                {
                    //Console.WriteLine("Successfully disconnected remote share: " + status2[1].Trim());
                    Logger.logging("copyPackage(): successfully disconnected from remote workstation");
                    Console.WriteLine("Successfully disconnected from remote workstation");
                }
                else
                {
                    Logger.logging("copyPackage(): failed to disconnect from remote workstation \"" + status2[2].Trim() + "\"");
                    Console.WriteLine("Remote share disconnection failed: \"" + status2[2].Trim() + "\"");
                }

            }
            else
            {
                if (status[2].IndexOf("1326", StringComparison.CurrentCultureIgnoreCase) >= 0)
                {
                    Console.WriteLine("copyPackage(): Failed to connect to remote workstation - Invalid username and/or password");
                }
                else
                {
                    Console.WriteLine("copyPackage(): Failed to connect to remote workstation - \"" + status[2].Trim() + "\"");
                }
            }
        }
        /// <summary>
        /// Start bdm.exe on remote machine
        /// </summary>
        /// <param name="workstation"></param>
        /// <param name="p"></param>
        public static void kickoffBdm(string workstation, Program p)
        {
            string nasLogin = p.getNasLogin();
            string user = p.getRemoteLogin();
            string pass = p.getPasswordDict()[workstation];
            string branch = p.getBranch(workstation);
            string adminShare = "admin$";
            string batFileName = "bdm.bat";
            string bmFile = "bm.csv";            
            string bdmPkg = "BdmPkg.exe";
            //use xcopy instead
            //string copyBmExe = "CopyBm.exe";

            //return if password is null/invalid
            if (string.IsNullOrEmpty(pass))
            {
                Logger.logging("kickoffBdm(): " + workstation + " unreacheable");
                Console.WriteLine("Skip " + workstation + " unreacheable");
                return;
            }

            // return if bdm is running
            try
            {
                if (SystemProcess.isBdmProcessExist(workstation, workstation, user, pass))
                {
                    p.addToBdmStatusDict(workstation, "running");
                    Logger.logging("kickoffBdm(): " + workstation + " bdm is running");
                    Console.WriteLine("bdm is running");
                    return;
                }
            } catch (Exception e)
            {
                Console.WriteLine("kickoffBdm() Exception: " + e.Message);
                p.addToBdmStatusDict(workstation, "unknown");
                Console.WriteLine("bdm unknown");
                return;
            }


            // create Dictionary of file to delete/copy to remote
            // key = local file name
            // value = remote file name with path
            Dictionary<string, string> fileDict = new Dictionary<string, string>();
            fileDict.Add(batFileName, @"\\" + workstation + "\\" + adminShare + "\\" + batFileName);
            fileDict.Add(bmFile, @"\\" + workstation + "\\" + adminShare + "\\" + bmFile);
            //use xcopy instead
            //fileDict.Add(copyBmExe, @"\\" + workstation + "\\" + adminShare + "\\" + copyBmExe);
            fileDict.Add(bdmPkg, @"\\" + workstation + "\\" + adminShare + "\\" + bdmPkg);

            List<string> status = new List<string>();

            // mount admin share via net use
            if (NetUse.connectShare(workstation, workstation, user, pass, "admin$", ref status))
            {
                //Console.WriteLine("Able to connect: " + status[1].Trim());
                Console.WriteLine("Successfully connected to remote workstation");

                //delete/copy file to remote
                foreach (KeyValuePair<string, string> file in fileDict)
                {
                    //delete remote bdm.bat (dictionary's value)
                    if (string.Equals(batFileName, file.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        if (File.Exists(file.Value))
                        {
                            Console.WriteLine("Delete remote file " + file.Key);
                            try
                            {
                                File.Delete(file.Value);
                            }
                            catch (Exception e)
                            {
                                Logger.logging("kickoffBdm() Exception: " + e.Message);
                                Console.WriteLine("kickoffBdm() Exception: " + e.Message);
                            }
                        }
                    }
                    else
                    {
                        // copy bm.csv, CopyBm.exe, BdmPkg.exe to remote
                        /*
                        if (File.Exists(file.Key) && File.Exists(file.Value) &&
                            File.GetCreationTime(file.Key).Equals(File.GetCreationTime(file.Value)))
                        {
                            Console.WriteLine(file.Key + " is latest so update not required");
                        }
                        else if (!File.Exists(file.Key))
                        {
                            Console.WriteLine("Local file " + file.Key + " is missing!");
                        }
                        else
                        {
                            Console.WriteLine("Update remote file " + file.Key);
                            try
                            {
                                File.Copy(file.Key, file.Value, true);
                                File.SetCreationTime(file.Value, File.GetCreationTime(file.Key));
                            }
                            catch (Exception e)
                            {
                                Logger.logging("kickoffBdm() Exception: " + e.Message);
                                Console.WriteLine("kickoffBdm() Exception: " + e.Message);
                            }
                        }*/
                        //just copy package
                        Console.WriteLine("Update remote file " + file.Key);
                        try
                        {
                            File.Copy(file.Key, file.Value, true);
                            File.SetCreationTime(file.Value, File.GetCreationTime(file.Key));
                        }
                        catch (Exception e)
                        {
                            Logger.logging("kickoffBdm() Exception: " + e.Message);
                            Console.WriteLine("kickoffBdm() Exception: " + e.Message);
                        }
                    }
                }

                try
                {
                    // append command to bat file                
                    StreamWriter sw_append = new StreamWriter(fileDict[batFileName], true);
                    //winzip hung so omit it, instead use self-extracting bdm package
                    //sw_append.WriteLine("\"c:\\program files\\winzip\\winzip32.exe\" -e -o c:\\temp\\bdm.zip c:\\temp");
                    sw_append.WriteLine("%systemroot%\\" + bdmPkg);
                    //use xcopy instead
                    //sw_append.WriteLine("%systemroot%\\" + copyBmExe);
                    sw_append.WriteLine("%systemroot%\\system32\\xcopy /f /y %systemroot%\\" + bmFile + " c:\\temp\\bdm");
                    sw_append.WriteLine("c:\\temp\\bdm\\bdm.exe -g -z -u " + nasLogin + " -e -b " + branch);
                    sw_append.Close();
                }
                catch (Exception e)
                {
                    Logger.logging("kickoffBdm() Exception: " + e.Message);
                    Console.WriteLine("kickoffBdm() Exception: " + e.Message);
                }

                try
                {

                    //create ConnectionOptions
                    ConnectionOptions connOptions = new ConnectionOptions();
                    connOptions.Username = user + "\\" + user;
                    connOptions.Password = pass;
                    connOptions.EnablePrivileges = true;

                    //create and connect ManagementScope object
                    ManagementScope manScope = new ManagementScope(String.Format(@"\\{0}\ROOT\CIMV2", workstation), connOptions);
                    manScope.Connect();

                    //create ObjectGetOptions object
                    ObjectGetOptions objectGetOptions = new ObjectGetOptions();

                    //create ManagementPath object new  process
                    ManagementPath managementPath = new ManagementPath("Win32_Process");

                    //hook up everything to the ManagementClass
                    ManagementClass processClass = new ManagementClass(manScope, managementPath, objectGetOptions);

                    ManagementBaseObject inParams = processClass.GetMethodParameters("Create");

                    //prepare command string
                    String command = batFileName;
                    inParams["CommandLine"] = command;

                    //calling invokemethod
                    Console.WriteLine("Initiate bdm");
                    Logger.initiatedLog(p.getNasLogin() + " " + workstation);
                    ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);
                    //Console.WriteLine("Creation of the process returned: " + outParams["returnValue"]);

                    String pid = Convert.ToString(outParams["processId"]);

                    //add workstation to bdmStatusDict dictionary
                    p.addToBdmStatusDict(workstation, "initiated");
                }
                catch (Exception e)
                {
                    Logger.logging("kickoffBdm() Exception: " + e.Message);
                    Console.WriteLine("kickoffBdm() Exception: " + e.Message);
                }

                //disconnect share
                List<string> status2 = new List<string>();
                if (NetUse.disconnectShare(workstation, workstation, user, pass, adminShare, ref status2))
                {
                    //Console.WriteLine("Successfully disconnected remote share: " + status2[1].Trim());
                    Logger.logging("kickoffBdm(): successfully disconnected from remote workstation");
                    Console.WriteLine("Successfully disconnected from remote workstation");
                }
                else
                {
                    Logger.logging("kickoffBdm(): failed to disconnect from remote workstation \"" + status2[2].Trim() + "\"");
                    Console.WriteLine("Remote share disconnection failed: \"" + status2[2].Trim() + "\"");
                }

            }
            else
            {
                if (status[2].IndexOf("1326", StringComparison.CurrentCultureIgnoreCase) >= 0)
                {
                    Console.WriteLine("kickoffBdm(): failed to connect to remote workstations - Invalid username and/or password");
                }
                else
                {
                    Console.WriteLine("kickoffBdm(): failed to connect to remote workstations - \"" + status[2].Trim() + "\"");
                }
            }
        }
        public static bool isWorkstationNameValid(string workstation, ref string branch)
        {
            int dummy;

            try
            {
                if (!string.IsNullOrEmpty(workstation) &&
                    ((workstation.Length == 11 && int.TryParse(workstation.Substring(1, 6), out dummy) && 
                    int.TryParse(workstation.Substring(8, 3), out dummy))))
                {
                    branch = workstation.Substring(1, 6);
                    return true;
                }
                else if (!string.IsNullOrEmpty(workstation) &&
                        ((workstation.Length == 12 && int.TryParse(workstation.Substring(2, 6), out dummy) &&
                        int.TryParse(workstation.Substring(9, 3), out dummy))))
                {
                    branch = workstation.Substring(2, 6);
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception e)
            {
                Logger.logging ("isWorkstationNameValid() Exception: " + e.Message);
                Console.WriteLine("isWorkstationNameValid() Exception: " + e.Message);
            }
            return false;
        }
        /// <summary>
        /// Get remote login name from user input
        /// </summary>
        /// <returns></returns>
        public static string getLoginInput()
        {
            string loginName = null;
            //Console.WriteLine("Current NAS login: " + p.getNasLogin());
            printNewLine();
            Console.Write("Enter NAS login: ");
            loginName = Console.ReadLine();
            return loginName;
        }
        /// <summary>
        /// 
        /// </summary>
        public static void displayHelp()
        {
            Console.Clear();
            Console.WriteLine("OneDeploy Available Commands");
            Console.WriteLine("----------------------------");
            printNewLine();
            Console.WriteLine("kickoff: start bdm on remote workstation");
            printNewLine();
            Console.WriteLine("copy: copy bdm package to remote workstation");
            printNewLine();
            Console.WriteLine("download: get log from remote workstation");
            printNewLine();
            Console.WriteLine("clear: clear console");
            printNewLine();
            Console.WriteLine("quit: terminate application");
            printNewLine();
            keyToContinue();
        }
        public static void displayKickoffHelp()
        {
            Console.Clear();
            Console.WriteLine("OneDeploy - Kickoff Available Commands");
            Console.WriteLine("--------------------------------------");
            printNewLine();
            Console.WriteLine("load: add workstations from a file");
            printNewLine();
            Console.WriteLine("refresh: refresh the workstation status");
            printNewLine();
            Console.WriteLine("remove: remove workstation from queue");
            printNewLine();
            Console.WriteLine("kill: terminate bdm on remote workstation");
            printNewLine();
            Console.WriteLine("quit: return to OneDeploy prompt");
            printNewLine();
            keyToContinue();
        }
        public static void displayCopyHelp()
        {
            Console.Clear();
            Console.WriteLine("OneDeploy - Copy Package Available Commands");
            Console.WriteLine("-------------------------------------------");
            printNewLine();
            Console.WriteLine("clear: remove workstations from queue");
            printNewLine();
            Console.WriteLine("quit: return to OneDeploy prompt");
            printNewLine();
            keyToContinue();
        }
        /// <summary>
        /// Check if string parameter contain any whitespace character
        /// </summary>
        /// <param name="value"></param>
        /// <returns>bool</returns>
        public static bool isNullOrWhiteSpace(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return true;
            }
            else
            {
                for (int i = 0; i < value.Length; i++)
                {
                    if (char.IsWhiteSpace(value[i]))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        /// <summary>
        /// Display password entered in masked char "*"
        /// </summary>
        /// <returns>string</returns>
        public static String enterPassword()
        {
            string password = null;
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);

                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                    {
                        password = password.Substring(0, (password.Length - 1));
                        Console.Write("\b \b");
                    }
                }
            } while (key.Key != ConsoleKey.Enter);

            //return password
            return password;
        }
        /// <summary>
        /// Get password with masked char "*" except for last two char
        /// </summary>
        /// <param name="password"></param>
        public static string getPasswordLast2Char(string password)
        {
            string tmp = null;

            if (!String.IsNullOrEmpty(password))
            {
                int passLength = password.Length;
                for (int i = 0; i < passLength; i++)
                {
                    if ((i == (passLength - 2)) || (i == (passLength - 1)))
                    {
                        tmp = tmp + password[i];
                    }
                    else
                    {
                        tmp = tmp + "*";
                    }
                }
            }

            return tmp;
        }
        /// <summary>
        /// Press any key to continue
        /// </summary>
        public static void keyToContinue()
        {
            Console.Write("Press any key to continue... ");
            String dummy;
            dummy = Console.ReadLine();
            Console.Clear();
        }
        /// <summary>
        /// Print string parameter to console
        /// </summary>
        /// <param name="msg"></param>
        public static void printToConsole(String msg)
        {
            Console.WriteLine(" " + msg);
        }
        /// <summary>
        /// Get user input
        /// </summary>
        /// <returns></returns>
        public static String getSelectedOption()
        {
            Console.Write(" Select an option: ");
            return Console.ReadLine();
        }
        /// <summary>
        /// Print new line
        /// </summary>
        public static void printNewLine()
        {
            Console.WriteLine();
        }
        /// <summary>
        /// Get domain
        /// </summary>
        /// <returns>string</returns>
        static public String getDomain()
        {
            Console.WriteLine("Enter domain: ");
            return Console.ReadLine();
        }
        /// <summary>
        /// Get username
        /// </summary>
        /// <returns></returns>
        static public String getUsername()
        {
            Console.WriteLine("Enter user name: ");
            return Console.ReadLine();
        }
        /// <summary>
        /// Get password
        /// </summary>
        /// <returns></returns>
        static public String getPassword()
        {
            Console.WriteLine("Enter password: ");
            return Console.ReadLine();
        }
    }


    /// <summary>
    /// System Process Class
    /// </summary>
    public class SystemProcess
    {
        public string name;
        public int pid;
        public int cpu;

        public SystemProcess(String name, int pid, int cpu)
        {
            this.name = name;
            this.pid = pid;
            this.cpu = cpu;
        }

        /// <summary>
        /// Print parameter string to console
        /// </summary>
        /// <param name="msg"></param>
        public static void printToConsole(String msg)
        {
            Console.WriteLine(" " + msg);
        }
        /// <summary>
        /// Print new line
        /// </summary>
        public static void printNewLine()
        {
            Console.WriteLine();
        }
        public static bool isBdmProcessExist(String wksName, String domain, String user, String pass)
        {
            bool bdmExist = false;
            string bdmProcessName = "bdm.exe";
            try
            {

                //define wmi remote connection object
                ConnectionOptions co = new ConnectionOptions();

                //use username if not empty
                if (!String.IsNullOrEmpty(user))
                {
                    co.Username = domain + "\\" + user;
                    co.Password = pass;
                }
                //else impersonate (default)

                //co.Authority = "ntlmdomain:DOMAIN";

                ManagementPath mPath = new ManagementPath(@"\\" + wksName + @"\root\cimv2");
                //ManagementScope mScope = new ManagementScope("\\\\" + wksName + "\\root\\CIMV2", co);
                ManagementScope mScope = new ManagementScope(mPath, co);

                mScope.Connect();

                //ObjectQuery oQuery = new ObjectQuery("SELECT * FROM Win32_PerfFormattedData_PerfProc_Process");
                ObjectQuery oQuery = new ObjectQuery("SELECT * FROM Win32_Process"); //Win32_Process prints bdm.exe as process name

                ManagementObjectSearcher mObjSearcher = new ManagementObjectSearcher(mScope, oQuery);

                ManagementObjectCollection getObjColl = mObjSearcher.Get();

                //add process to list
                foreach (ManagementObject mObj in getObjColl)
                {
                    string pName = (String)mObj["name"];
                    //Console.WriteLine(pName);
                    if (pName.IndexOf(bdmProcessName, StringComparison.CurrentCultureIgnoreCase) >= 0)
                    {
                        bdmExist = true;
                    }
                }

            }
            catch (Exception e)
            {
                Logger.logging("isBdmProcessExist() Exception: " + e.Message);
                Console.WriteLine("isBdmProcessExist() Exception: " + e.Message);
                throw new Exception(@e.Message, e);
            }
            return bdmExist;
        }
        /// <summary>
        /// Check if process exists
        /// </summary>
        /// <param name="workstation"></param>
        /// <param name="domain"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="pid"></param>
        /// <returns>bool</returns>
        public static bool isProcessExist(String workstation, String domain, String username, String password, string pid)
        {
            try
            {

                //define wmi remote connection object
                ConnectionOptions co = new ConnectionOptions();

                //use username if available
                if (!String.IsNullOrEmpty(username))
                {
                    co.Username = domain + "\\" + username;
                    co.Password = password;
                }
                //else impersonate (default)

                //co.Authority = "ntlmdomain:DOMAIN";

                ManagementPath mPath = new ManagementPath(@"\\" + workstation + @"\root\cimv2");
                //ManagementScope mScope = new ManagementScope("\\\\" + wksName + "\\root\\CIMV2", co);
                ManagementScope mScope = new ManagementScope(mPath, co);

                mScope.Connect();

                //ObjectQuery oQuery = new ObjectQuery("SELECT * FROM Win32_Process");
                ObjectQuery oQuery = new ObjectQuery("SELECT * FROM Win32_PerfFormattedData_PerfProc_Process");

                ManagementObjectSearcher mObjSearcher = new ManagementObjectSearcher(mScope, oQuery);

                ManagementObjectCollection getObjColl = mObjSearcher.Get();

                //add process to list
                foreach (ManagementObject mObj in getObjColl)
                {
                    if (string.Equals(pid, Convert.ToString(mObj["idprocess"]), StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

            }
            catch (Exception e)
            {
                printNewLine();
                Logger.logging("isProcessExist() Exception: " + e.Message);
                printToConsole("isProcessExist() Exception: " + e.Message);
            }

            return false;
        }
        /// <summary>
        /// Kill process pid
        /// </summary>
        /// <param name="workstation"></param>
        /// <param name="domain"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="pid"></param>
        /// <returns>bool</returns>
        public static bool killProcess(string workstation, string domain, string username, string password, string pid)
        {
            //create ConnectionOptions object
            ConnectionOptions connOptions = new ConnectionOptions();
            //connOptions.Impersonation = ImpersonationLevel.Impersonate;

            //use username if available
            if (!string.IsNullOrEmpty(username))
            {
                connOptions.Username = domain + "\\" + username;
                connOptions.Password = password;
            }
            //else impersonate (default)

            //connOptions.EnablePrivileges = true;

            //create and connect ManagementScope object
            ManagementScope manScope = new ManagementScope(String.Format(@"\\{0}\ROOT\CIMV2", workstation), connOptions);
            manScope.Connect();

            //create ObjectGetOptions object
            ObjectGetOptions objectGetOptions = new ObjectGetOptions();

            //create ManagementPath object new  process
            ManagementPath managementPath = new ManagementPath("Win32_Process");

            //hook up everything to the ManagementClass
            ManagementClass processClass = new ManagementClass(manScope, managementPath, objectGetOptions);

            ManagementBaseObject inParams = processClass.GetMethodParameters("Create");

            //prepare command string to kill
            String command = "taskkill /f /pid " + pid;
            inParams["CommandLine"] = command;

            //calling invokemethod to kill process
            ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);
            //Console.WriteLine("Creation of the process returned: " + outParams["returnValue"]);
            //Console.WriteLine("Process ID: " + outParams["processId"]);

            if (isProcessExist(workstation, domain, username, password, pid))
            {
                return true;
            }
            else
            {
                return false;
            }

        }
        public static string getBdmProcessId(string wksName, string domain, string user, string pass)
        {
            string bdmProcessName = "bdm.exe";
            string pid = "-1";
            try
            {

                //define wmi remote connection object
                ConnectionOptions co = new ConnectionOptions();

                //use username if not empty
                if (!String.IsNullOrEmpty(user))
                {
                    co.Username = domain + "\\" + user;
                    co.Password = pass;
                }
                //else impersonate (default)

                //co.Authority = "ntlmdomain:DOMAIN";

                ManagementPath mPath = new ManagementPath(@"\\" + wksName + @"\root\cimv2");
                //ManagementScope mScope = new ManagementScope("\\\\" + wksName + "\\root\\CIMV2", co);
                ManagementScope mScope = new ManagementScope(mPath, co);

                mScope.Connect();

                //ObjectQuery oQuery = new ObjectQuery("SELECT * FROM Win32_PerfFormattedData_PerfProc_Process");
                ObjectQuery oQuery = new ObjectQuery("SELECT * FROM Win32_Process"); //Win32_Process prints bdm.exe as process name

                ManagementObjectSearcher mObjSearcher = new ManagementObjectSearcher(mScope, oQuery);

                ManagementObjectCollection getObjColl = mObjSearcher.Get();

                //add process to list
                foreach (ManagementObject mObj in getObjColl)
                {
                    string pName = (string)mObj["name"];
                    //Console.WriteLine(pName);
                    if (pName.IndexOf(bdmProcessName, StringComparison.CurrentCultureIgnoreCase) >= 0)
                    {
                        pid = Convert.ToString(mObj["processId"]);
                    }
                }

            }
            catch (Exception e)
            {
                Logger.logging("getBdmProcessId() Exception: " + e.Message);
                Console.WriteLine("getBdmProcessId() Exception: " + e.Message);
            }

            //return pid
            return pid;
        }
    }

    /// <summary>
    /// Net Use Class
    /// </summary>
    public class NetUse
    {
        public static void printToConsole(String msg)
        {
            Console.WriteLine(" " + msg);
        }
        /// <summary>
        /// Use windows command "net use" to connect network share
        /// </summary>
        /// <param name="workstation"></param>
        /// <param name="domain"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="share"></param>
        /// <param name="status"></param>
        /// <returns>bool</returns>
        public static bool connectShare(String workstation, String domain, String username, String password, String share, ref List<string> status)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.CreateNoWindow = true;
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            String sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
            startInfo.FileName = sysRoot + "\\system32\\net.exe";
            startInfo.Arguments = "use \\\\" + workstation + "\\" + share + " /user:" + domain + "\\" + username + " " + password;

            //Console.WriteLine("\n" + startInfo.FileName + " " + startInfo.Arguments);
            int exitCode = 1;
            String stdOut = null;
            String stdErr = null;
            try
            {
                //Start the process with the info we specified
                //Call WaitForExit and then the using statement will close
                using (Process exeProcess = Process.Start(@startInfo))
                {
                    //stdout
                    stdOut = exeProcess.StandardOutput.ReadToEnd();

                    //stderr
                    stdErr = exeProcess.StandardError.ReadToEnd();

                    //wait for process to exit
                    exeProcess.WaitForExit();

                    //assign process exitcode
                    exitCode = exeProcess.ExitCode;

                    //add exit code(0), stdout(1), stderr(2) to ref list
                    status.Add(Convert.ToString(exitCode));
                    status.Add(stdOut);
                    status.Add(stdErr);
                }
            }
            catch (Exception e)
            {
                printNewLine();
                Logger.logging("connectShare() Exception: " + e.Message.ToString());
                printToConsole("connectShare() Exception: " + e.Message.ToString());
            }
            //0 -> successful
            //2 + stdErr("1219") -> share already connected -> return successful
            //else -> failed -> return failed            
            if (exitCode == 0 || ((exitCode == 2) &&
                stdErr.IndexOf("1219", StringComparison.CurrentCultureIgnoreCase) >= 0))
            {
                return true;
            }
            else
            {
                //print error and return false
                if (status[2].IndexOf("1326", StringComparison.CurrentCultureIgnoreCase) >= 0)
                {
                    printToConsole(" - connectShare(): Invalid username and/or password");
                }
                else
                {
                    //Console.WriteLine(" - connectShare(): Unable to connect: \"" + status[2].Trim() + "\"");
                    Console.WriteLine(" - connectShare(): Unable to connect");
                }
                return false;
            }
        }
        public static void printNewLine()
        {
            Console.WriteLine();
        }
        /// <summary>
        /// Use windows command "net use" to disconnect network share
        /// </summary>
        /// <param name="workstation"></param>
        /// <param name="domain"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="share"></param>
        /// <param name="status"></param>
        /// <returns>bool</returns>
        public static bool disconnectShare(String workstation, String domain, String username, String password, String share, ref List<string> status)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.CreateNoWindow = true;
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            String sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
            startInfo.FileName = sysRoot + "\\system32\\net.exe";
            startInfo.Arguments = "use /delete /y \\\\" + workstation + "\\" + share;
            //Console.WriteLine("\n" + startInfo.FileName + " " + startInfo.Arguments);
            int exitCode = 1;
            String stdOut = null;
            String stdErr = null;
            try
            {
                // Start the process with the info we specified.
                // Call WaitForExit and then the using statement will close.
                using (Process exeProcess = Process.Start(@startInfo))
                {
                    //stdout
                    stdOut = exeProcess.StandardOutput.ReadToEnd();

                    //stderr
                    stdErr = exeProcess.StandardError.ReadToEnd();

                    //wait for process to exit
                    exeProcess.WaitForExit();

                    //assign process exitcode
                    exitCode = exeProcess.ExitCode;

                    //add exit code, stdout, stderr to ref list
                    status.Add(Convert.ToString(exitCode));
                    status.Add(stdOut);
                    status.Add(stdErr);


                }
            }
            catch (Exception e)
            {
                printNewLine();
                Logger.logging("disconnectShare() Exception: " + e.Message.ToString());
                printToConsole("disconnectShare() Exception: " + e.Message.ToString());
            }

            //0 -> successful
            //else -> failed -> return failed            
            if (exitCode == 0)
            {
                return true;
            }
            else
            {
                return false;
            }

        }
    }

    //Class to log message for debugging
    public class Logger
    {
        public static void logging(string message)
        {
            //set log file name
            string file = "onedeploy.log";

            //create stream writer
            StreamWriter sw = null;

            //write message to file
            try
            {
                //create object to append content to file
                sw = new StreamWriter(file, true);
                sw.WriteLine(DateTime.Now.ToString("MM/dd/yy HH:mm") + " " + message);
            }
            catch (Exception e)
            {
                Console.WriteLine("logging() exception: " + e.Message);
            }
            finally
            {
                try
                {
                    sw.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine("logging() exception: " + e.Message);
                }
            }
        }
        public static void initiatedLog(string message)
        {
            //set log file name
            string file = "initiated.log";

            //create stream writer
            StreamWriter sw = null;

            //write message to file
            try
            {
                //create object to append content to file
                sw = new StreamWriter(file, true);
                sw.WriteLine(DateTime.Now.ToString("MM/dd/yy HH:mm") + " " + message);
            }
            catch (Exception e)
            {
                Console.WriteLine("initiatedLog() exception: " + e.Message);
            }
            finally
            {
                try
                {
                    sw.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine("initiatedLog() exception: " + e.Message);
                }
            }
        }
    }
}