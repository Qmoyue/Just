package io.just.sast.report;

/** 扫描统计。 */
public record ScanStatistics(
        int filesScanned, int classesLoaded, int diagnostics,
        int sinksMarked, int magicEntries, int chainsFound,
        long elapsedMs, long heapUsedMb) {

    public static ScanStatistics empty() {
        return new ScanStatistics(0, 0, 0, 0, 0, 0, 0, 0);
    }
}
