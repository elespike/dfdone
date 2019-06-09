import sys


def main():
    print("test-- inside main")
    print("args:")

    args = sys.argv[1:]
    for arg in args:
        print("[arg] passed arg == {arg}".format(arg=arg))


if __name__ == '__main__':
    main()
