const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const moc_step = b.addSystemCommand(&.{"/usr/lib/qt6/moc"});
    moc_step.addFileArg(b.path("src/ConnectWindow.h"));
    moc_step.addArg("-o");
    const moc_connectwindow = moc_step.addOutputFileArg("moc_ConnectWindow.cpp");

    const exe = b.addExecutable(.{
        .name = "sneeze-qt",
        .target = target,
        .optimize = optimize,
    });
    exe.addCSourceFiles(.{
        .root = b.path("src"),
        .files = &.{ "main.cpp", "ConnectWindow.cpp" },
    });
    exe.addCSourceFile(.{ .file = moc_connectwindow });
    //exe.addIncludePath(.{ .cwd_relative = "/usr/include/qt6/QtCore" });
    //exe.addIncludePath(.{ .cwd_relative = "/usr/include/qt6/QtWidgets" });
    exe.linkLibCpp();
    exe.linkSystemLibrary("Qt6Core");
    exe.linkSystemLibrary("Qt6Widgets");

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
