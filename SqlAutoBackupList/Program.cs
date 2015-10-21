using System;
using System.Collections.Generic;
using System.IO;

using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;

using NDesk.Options;

namespace SqlAutoBackupList
{
	class Options
	{
		public string StorageAccount { get; set; }
		public string StorageKey { get; set; }
		public string StorageContainer { get; set; }
		public string SqlServerCredential { get; set; }
		public bool ShowHelp { get; set; }
		public string Database { get; set; }
	}

	enum BackupType
	{
		Full,
		Log
	};

	class BackupFile
	{
		public CloudPageBlob Blob { get; set; }
		public string DatabaseName { get; set; }
		public DateTimeOffset LastModified { get; set; }
		public BackupType BackupType { get; set; }
	}

	class BackupSet
	{
		public string DatabaseName { get; set; }
		public DateTimeOffset LastModified { get; set; }
		public List<BackupFile> BackupFiles { get; set; }
	}

	class Program
	{
		static void Main(string[] args)
		{
			var options = GetOptions(args);
			if (options.ShowHelp)
			{
				Console.WriteLine(
@"Usage: SqlAutoBackupList.exe
	--account= Name of your Azure Storage Account
	--key= One of your Azure Storage Account's keys
	--container= Name of your SQL Server backup container
	--credential= Name of the SQL Server credential to use when accessing the blobs during restore
    [--database=] Name of a specific database to use

* Note: This program won't actually modify any SQL Server data, all it does is print out the RESTORE commands
*       that you need to restore each of your databases. It's up to you to copy these and execute them yourself
");
				return;
			}

			var credentials = new StorageCredentials(options.StorageAccount, options.StorageKey);
			var account = new CloudStorageAccount(credentials, useHttps: true);
			var client = account.CreateCloudBlobClient();
			var container = client.GetContainerReference(options.StorageContainer);

			// Get a list of all the files in the container and build a list of the ones that
			// look like database backup files
			var files = new List<BackupFile>();
			var prefix = String.IsNullOrWhiteSpace(options.Database) ? null : String.Format("{0}_", options.Database);
			foreach (var iblob in container.ListBlobs(useFlatBlobListing: true, prefix: prefix))
			{
				var blob = iblob as CloudPageBlob;
				if (blob == null) continue;

				var backupType = GetBackupType(blob);
				if (backupType == null) continue;

				var nameParts = blob.Name.Split('_');
				if (nameParts.Length != 3) continue;
				string databaseName = nameParts[0];

				files.Add(new BackupFile
				{
					Blob = blob,
					BackupType = backupType.Value,
					DatabaseName = databaseName,
					LastModified = blob.Properties.LastModified.Value
				});
			}

			// Sort them by database name and from newest -> oldest
			files.Sort((a,b) =>
			{
				var nameSort = String.Compare(a.DatabaseName, b.DatabaseName);
				if (nameSort != 0) return nameSort;

				return DateTimeOffset.Compare(a.LastModified, b.LastModified) * -1;
			});

			// Group the files into backup sets
			var sets = new List<BackupSet>();
			BackupSet currentSet = null;
			foreach (var file in files)
			{
				if (currentSet == null)
				{
					currentSet = new BackupSet
					{
						DatabaseName = file.DatabaseName,
						LastModified = file.LastModified,
						BackupFiles = new List<BackupFile>()
					};
					sets.Add(currentSet);
				}

				currentSet.BackupFiles.Add(file);

				if (file.BackupType == BackupType.Full) currentSet = null;
			}

			// Group all the backup sets together by which database they represent
			var databases = new Dictionary<string, List<BackupSet>>();
			foreach (var set in sets)
			{
				if (!databases.ContainsKey(set.DatabaseName)) databases.Add(set.DatabaseName, new List<BackupSet>());
				databases[set.DatabaseName].Add(set);
			}

			// Dump out the RESTORE commands for the most recent backup set for each database
			foreach (var database in databases)
			{
				var latestSet=database.Value[0];
				Console.WriteLine("-- Restore the {0} database", database.Key);
				for (int i = latestSet.BackupFiles.Count -1 ; i >= 0 ; i--)
				{
					var file = latestSet.BackupFiles[i];
					Console.WriteLine("RESTORE {0} [{1}] FROM URL = N'{2}' WITH CREDENTIAL = N'{3}', {4}RECOVERY, FILE = 1, NOUNLOAD, STATS = 5",
						file.BackupType == BackupType.Full? "DATABASE" : "LOG",
						file.DatabaseName,
						file.Blob.Uri,
						options.SqlServerCredential,
						i > 0? "NO" : "");
				}
				Console.WriteLine();
			}
		}

		static BackupType? GetBackupType(CloudPageBlob blob)
		{
			switch (Path.GetExtension(blob.Name).ToLower())
			{
				case ".log": return BackupType.Log;
				case ".bak": return BackupType.Full;
			}

			return null;
		}

		static Options GetOptions(string[] args)
		{
			var options = new Options {  SqlServerCredential = "DUMMY" };

			var parameters = new OptionSet
			{
				{ "account=", x => options.StorageAccount = x },
				{ "key=", x => options.StorageKey = x },
				{ "container=", x => options.StorageContainer = x },
				{ "credential=", x => options.SqlServerCredential = x },
				{ "database=", x => options.Database = x },
				{ "help", x => options.ShowHelp = true }
			};

			try
			{
				var extra = parameters.Parse(args);
				if (extra.Count > 0) options.ShowHelp = true;
				options.ShowHelp |= options.StorageAccount == null;
				options.ShowHelp |= options.StorageKey == null;
				options.ShowHelp |= options.StorageContainer == null;
			}
			catch
			{
				options.ShowHelp = true;
			}

			return options;
		}
	}
}
