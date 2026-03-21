using System.Reflection;

namespace CipheredFileStream.Test.IO;

/// <summary>
/// Shared budget for all torture/endurance tests. Auto-discovers how many endurance
/// test classes exist via reflection, then divides the total disk budget equally.
///
/// Environment variables:
///   ENDURANCE_DISK_MB  — total disk budget for ALL concurrent torture tests (default: auto-detect)
///   ENDURANCE_MINUTES  — test duration in minutes (default: 0.5 = 30s)
///   ENDURANCE_TASKS    — parallel task count per test (default: 10)
///   CFS_TEST_TEMP      — temp file directory (default: system temp)
///
/// Disk budget formula per test class:
///   perTestBudget = ENDURANCE_DISK_MB / tortureTestCount
///
/// Per-task file size budget (within each test):
///   Bucket weights: Small=1, Medium=10, Large=100, VeryLarge=1000
///   Task i -> bucket by position: [0%,50%)=S, [50%,75%)=M, [75%,92%)=L, [92%,100%)=VL
///   totalWeight = sum(weight(bucket(i))) for all tasks
///   maxFileSize(i) = perTestBudget * weight(bucket(i)) / (totalWeight * safetyFactor)
///   safetyFactor = 2.5 (2 concurrent files + overhead + growth)
/// </summary>
[CollectionDefinition("TortureTests")]
public class TortureTestCollection : ICollectionFixture<TortureTestBudget> { }

public class TortureTestBudget
{
    private const double SafetyFactor = 2.5;

    private static readonly (double fraction, int weight)[] Buckets =
    {
        (0.50, 1),      // Small
        (0.75, 10),     // Medium
        (0.92, 100),    // Large
        (1.00, 1000),   // Very Large
    };

    /// <summary>Total disk budget in bytes for this test class.</summary>
    public long PerTestBudgetBytes { get; }

    /// <summary>Test duration.</summary>
    public TimeSpan Duration { get; }

    /// <summary>Number of parallel tasks per test.</summary>
    public int TaskCount { get; }

    /// <summary>Base directory for temp files.</summary>
    public string TempDir { get; }

    /// <summary>Number of torture test classes discovered in the assembly.</summary>
    public int TortureTestCount { get; }

    /// <summary>Total disk budget in MB (before splitting across tests).</summary>
    public long TotalDiskBudgetMB { get; }

    public TortureTestBudget()
    {
        double minutes = double.TryParse(Environment.GetEnvironmentVariable("ENDURANCE_MINUTES"), out var m) ? m : 0.5;
        TaskCount = int.TryParse(Environment.GetEnvironmentVariable("ENDURANCE_TASKS"), out var t) ? t : 10;
        TempDir = Environment.GetEnvironmentVariable("CFS_TEST_TEMP") ?? Path.GetTempPath();
        Duration = TimeSpan.FromMinutes(minutes);

        // Disk budget: explicit env var, or auto-detect from free space
        long diskMB;
        if (long.TryParse(Environment.GetEnvironmentVariable("ENDURANCE_DISK_MB"), out var d))
        {
            diskMB = d;
        }
        else
        {
            try
            {
                long freeBytes = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(TempDir))!).AvailableFreeSpace;
                long freeMB = freeBytes / (1024 * 1024);
                diskMB = Math.Min(500, freeMB * 60 / 100);
            }
            catch
            {
                diskMB = 500;
            }
        }

        // Count torture test classes that accept TortureTestBudget in their constructor
        TortureTestCount = Assembly.GetExecutingAssembly().GetTypes()
            .Count(type => type.GetConstructors()
                .Any(ctor => ctor.GetParameters()
                    .Any(p => p.ParameterType == typeof(TortureTestBudget))));

        TortureTestCount = Math.Max(TortureTestCount, 1);
        TotalDiskBudgetMB = diskMB;
        PerTestBudgetBytes = diskMB * 1024 * 1024 / TortureTestCount;
    }

    /// <summary>
    /// Compute max file size for a specific task based on its position and the budget.
    /// </summary>
    public long GetMaxFileSizeForTask(int taskId)
    {
        int weight = GetBucketWeight(taskId, TaskCount);
        long totalWeight = ComputeTotalWeight(TaskCount);
        long maxSize = (long)(PerTestBudgetBytes * (double)weight / (totalWeight * SafetyFactor));
        return Math.Max(maxSize, 1024); // at least 1KB
    }

    public static int GetBucketWeight(int taskId, int taskCount)
    {
        double position = (double)taskId / Math.Max(taskCount, 1);
        foreach (var (fraction, weight) in Buckets)
        {
            if (position < fraction)
                return weight;
        }
        return Buckets[^1].weight;
    }

    public static long ComputeTotalWeight(int taskCount)
    {
        long total = 0;
        for (int i = 0; i < taskCount; i++)
            total += GetBucketWeight(i, taskCount);
        return Math.Max(total, 1);
    }

    public string FormatSummary()
    {
        bool autoDetected = Environment.GetEnvironmentVariable("ENDURANCE_DISK_MB") == null;
        return $"Disk budget: {TotalDiskBudgetMB}MB total{(autoDetected ? " (auto-detected)" : "")}, " +
               $"{PerTestBudgetBytes / (1024 * 1024)}MB per test ({TortureTestCount} torture tests), " +
               $"Tasks: {TaskCount}, Duration: {Duration.TotalMinutes:F1}min, " +
               $"TempDir: {TempDir}, " +
               $"VL max file: {GetMaxFileSizeForTask(TaskCount - 1) / (1024 * 1024)}MB";
    }
}
