import megastone as ms

def alt_list(alts):
    if len(alts) > 0:
        return '(' + ', '.join(alts) + ')'
    return ''

def main():
    for format in ms.ExecFormat.all():
        print(f'{format.name} {alt_list(format.alt_names)}', end='')
        if format.magic is not None:
            print(f' magic: {format.magic.hex().upper()}', end='')
        print()

if __name__ == '__main__':
    main()