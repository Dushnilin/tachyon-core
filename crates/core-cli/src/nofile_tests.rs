use std::os::unix::process::CommandExt;
use std::process::Command;

#[test]
fn inherited_limits() {
    const CHILD_CASE: &str = "TACHYON_NOFILE_TEST_CASE";
    let mut inherited = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut inherited) },
        0
    );
    let cases: [(libc::rlim_t, libc::rlim_t, libc::rlim_t); 4] = [
        (1024, 4096, 4096),
        (1024, 65535, 65535),
        (70000, 70000, 70000),
        (1024, 70000, 65535),
    ]
    .map(|(soft, hard, expected)| {
        // Unprivileged runners cannot raise their inherited hard limit.
        (
            soft.min(inherited.rlim_max),
            hard.min(inherited.rlim_max),
            expected.min(inherited.rlim_max),
        )
    });
    if let Ok(index) = std::env::var(CHILD_CASE) {
        let (_, hard, expected) = cases[index.parse::<usize>().unwrap()];
        unsafe {
            super::raise_rlimit_nofile();
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            assert_eq!(limit.rlim_cur, expected);
            assert_eq!(limit.rlim_max, hard);
        }
        return;
    }
    // Change resource limits only in child processes, never in the test runner.
    for (index, (soft, hard, _)) in cases.into_iter().enumerate() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "nofile_tests::inherited_limits", "--nocapture"]);
        command.env(CHILD_CASE, index.to_string());
        unsafe {
            command.pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: soft,
                    rlim_max: hard,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        assert!(command.status().unwrap().success(), "case {index}");
    }
}
