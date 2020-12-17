import hashlib
import operator
import os
import pathlib
import struct
import typing as tp

from pyvcs.objects import hash_object


class GitIndexEntry(tp.NamedTuple):
    # @see: https://github.com/git/git/blob/master/Documentation/technical/index-format.txt
    ctime_s: int
    ctime_n: int
    mtime_s: int
    mtime_n: int
    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    size: int
    sha1: bytes
    flags: int
    name: str

    def pack(self) -> bytes:
        return struct.pack(
            "!LLLLLLLLLL20sH"
            + str(len(self.name))
            + "s"
            + str(8 - (62 + len(self.name)) % 8)
            + "x",
            self.ctime_s,
            self.ctime_n,
            self.mtime_s,
            self.mtime_n,
            self.dev,
            self.ino,
            self.mode,
            self.uid,
            self.gid,
            self.size,
            self.sha1,
            self.flags,
            self.name.encode(),
        )

    @staticmethod
    def unpack(data: bytes) -> "GitIndexEntry":
        index_unpacked_things = struct.unpack("!LLLLLLLLLL20sH" + str(len(data) - 62) + "s", data)
        return GitIndexEntry(
            *(
                list(index_unpacked_things[:-1])
                + [index_unpacked_things[-1].rstrip(b"\00").decode()]
            )
        )


def read_index(gitdir: pathlib.Path):
    indexes: list = []
    if not os.path.exists(str(gitdir) + os.path.sep + "index"):
        return indexes
    with open(str(gitdir) + os.path.sep + "index", "rb") as f:
        index = f.read()
        amount = struct.unpack("!i", index[8:12])[0]
        entr = index[12:]
        for element in range(amount):
            entry = entr[:62]
            in_len = struct.unpack("!H", entry[60:])[0]
            name = entr[62 : 62 + in_len].decode()
            (
                ctime_s,
                ctime_n,
                mtime_s,
                mtime_n,
                dev,
                ino,
                mode,
                uid,
                gid,
                size,
                sha1,
                flags,
            ) = struct.unpack("!LLLLLLLLLL20sH", entry)
            class_ind = GitIndexEntry(
                ctime_s,
                ctime_n,
                mtime_s,
                mtime_n,
                dev,
                ino,
                mode,
                uid,
                gid,
                size,
                sha1,
                flags,
                name,
            )
            indexes.append(class_ind)
            entr = entr[62 + in_len :]
            D = 0
            while entr[:D].replace(b"\x00", b"") == b"":
                D += 1
            D = D - 1 if D > 0 else 0
            entr = entr[D:]
        return indexes


def write_index(gitdir: pathlib.Path, entries: tp.List[GitIndexEntry]) -> None:
    sign = b"DIRC"
    ver = 2
    header = struct.pack("!4sLL", sign, ver, len(entries))
    packed_entries = b""
    for element in entries:
        packed_entries += element.pack()
    content = header + packed_entries
    dig = hashlib.sha1(content).digest()

    with open(str(gitdir) + os.path.sep + "index", "wb") as f:
        f.write(content + dig)


def ls_files(gitdir: pathlib.Path, details: bool = False) -> None:
    for element in read_index(gitdir):
        if details:
            stage = (element.flags >> 12) & 3
            print("{:6o} {} {:}\t{}".format(element.mode, element.sha1.hex(), stage, element.path))
        else:
            print(element.path)


def update_index(gitdir: pathlib.Path, paths: tp.List[pathlib.Path], write: bool = True) -> None:
    entry = {entry.name: entry for entry in read_index(gitdir)}
    for path in paths:
        if str(path) in entry:
            del entry[str(path)]
        with path.open("rb") as f:
            data = f.read()
        stat = os.stat(path)
        sha1 = hash_object(data, "blob", write=True)
        entry.update(
            {
                str(path): GitIndexEntry(
                    ctime_s=int(stat.st_ctime),
                    ctime_n=stat.st_ctime_ns % len(str(int(stat.st_ctime))),
                    mtime_s=int(stat.st_mtime),
                    mtime_n=stat.st_mtime_ns % len(str(int(stat.st_mtime))),
                    dev=stat.st_dev,
                    ino=stat.st_ino,
                    mode=stat.st_mode,
                    uid=stat.st_uid,
                    gid=stat.st_gid,
                    size=stat.st_size,
                    sha1=bytes.fromhex(sha1),
                    flags=7,
                    name=str(path),
                )
            }
        )
    if write:
        entry_list = []
        for name in sorted(entry.keys()):
            entry_list.append(entry[name])
        write_index(gitdir, entry_list)
