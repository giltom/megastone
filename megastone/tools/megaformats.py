import megastone as ms

def alt_list(alts):
    if len(alts) > 0:
        return '(' + ', '.join(alts) + ')'
    return ''

def main():
    for format in ms.ExecFormat.all():
        print(f'{format.name} {alt_list(format.alt_names)}')
        if len(format.extensions) > 0:
            extensions = ' '.join('.' + ext for ext in format.extensions)
            print(f'    extensions: {extensions}')
        if format.magic is not None:
            print(f'    magic: {format.magic.hex().upper()}')
        print()

if __name__ == '__main__':
    main()