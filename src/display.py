#!/usr/bin/env python3
"""Presentation only: consume V2 JSON, preserve JSON for non-terminal callers."""
import json
import os
import shlex
import sys


def main():
    mirror = os.environ.get('MIST_IPV6_UI') == 'stderr'
    human = sys.stdout.isatty() or mirror
    output = sys.stderr if mirror else sys.stdout
    color = (mirror or output.isatty()) and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb'

    def say(text='', tone='0'):
        prefix = '\033[' + tone + 'm' if color else ''
        suffix = '\033[0m' if color else ''
        print(prefix + str(text) + suffix, file=output, flush=True)

    def owners(data):
        value = data.get('owners')
        if isinstance(value, dict) and value:
            say('  Сеть: ' + '; '.join(str(k) + ': ' + str(v) for k, v in value.items()), '36')

    if human:
        say('\nMIST | IPv6 V2.3', '1;36')
        if os.environ.get('MIST_IPV6_VERIFIED_SHA'):
            say('[OK] Контрольная сумма исходника проверена', '32')
        if os.environ.get('MIST_IPV6_SAVED_SOURCE'):
            say('  Скрипт: ' + os.environ['MIST_IPV6_SAVED_SOURCE'], '90')
        say('[...] Выполнение и проверка состояния сети...', '36')

    for raw in sys.stdin:
        if mirror or not human:
            sys.stdout.write(raw)
            sys.stdout.flush()
        if not human:
            continue
        try:
            item = json.loads(raw)
        except (ValueError, TypeError):
            say(raw.rstrip('\r\n'))
            continue
        if not isinstance(item, dict):
            say(raw.rstrip('\r\n'))
            continue
        status = item.get('status')
        say()
        if status == 'NOOP':
            say('[OK] IPv6 уже отключён. Изменения не требуются.', '1;32')
            owners(item)
        elif status == 'AWAITING_CONFIRMATION':
            say('[OK] IPv6 отключён. Локальные проверки пройдены.', '32')
            owners(item)
            say('[ЖДЁТ] Подтвердите результат до истечения страховки.', '1;33')
            seconds = item.get('seconds')
            if seconds is not None:
                say('  Страховка: ' + str(seconds) + ' с осталось до автоотката.', '33')
            transaction = item.get('transaction')
            tool = item.get('tool')
            if transaction:
                say('  Резервная копия: ' + str(transaction), '36')
            if isinstance(tool, str) and isinstance(transaction, str):
                say('  После проверки доступности выполните одну команду:', '33')
                confirm = ('bash ' + shlex.quote(tool) + ' --confirm ' + shlex.quote(transaction)
                           + ' | python3 ' + shlex.quote(os.path.abspath(__file__)))
                say('  bash -o pipefail -c ' + shlex.quote(confirm), '1;36')
            say('  Без подтверждения автоматический откат останется включён.', '33')
        elif status == 'COMMITTED':
            say('[OK] Результат подтверждён. Автооткат отменён.', '1;32')
            if item.get('transaction'):
                say('  Резервная копия сохранена: ' + str(item['transaction']), '36')
        elif status == 'ROLLED_BACK':
            say('[ВОЗВРАТ] Исходные настройки восстановлены.', '1;33')
            if item.get('transaction'):
                say('  Резервная копия: ' + str(item['transaction']), '36')
        elif status == 'RESTORE_NOOP':
            say('[OK] Повторное восстановление не требуется.', '32')
            say('  Состояние: ' + str(item.get('previous', 'unknown')), '90')
        elif status == 'IPV4_POLICY_REINSTATED':
            say('[ИНФО] Правила маршрутизации IPv4 восстановлены из снимка.', '33')
            say('  Итоговая проверка продолжается.', '36')
        elif status == 'CHECK_OK':
            say('[OK] Проверка завершена. Сеть не изменялась.', '1;32')
            owners(item)
            say('  IPv6 сейчас: ' + ('отключён' if item.get('ipv6_disabled') else 'ещё не полностью отключён'), '36')
        elif status == 'STOP':
            say('[СТОП] Операция остановлена.', '1;31')
            say('  Причина: ' + str(item.get('reason', 'не указана')), '31')
            if item.get('error_code'):
                say('  Код: ' + str(item['error_code']), '31')
            if item.get('same_boot') is False:
                say('  Сервер перезагружен: подтверждение закрыто; страховка: ' + str(item.get('watchdog_active')), '33')
            elif 'remaining_seconds' in item:
                say('  До автоотката: ' + str(item['remaining_seconds']) + ' с; страховка: ' + str(item.get('watchdog_active')), '33')
        elif status == 'STATUS':
            say('[ИНФО] Состояние сохранённых операций', '1;36')
            for tx in item.get('transactions', []):
                state = tx.get('status', 'unknown')
                tone = '32' if state == 'committed' else '31' if state == 'restore_failed' else '33'
                say('  ' + str(tx.get('transaction', '')) + ': ' + str(state), tone)
                if tx.get('same_boot') is False:
                    say('    Сервер перезагружен: подтверждение закрыто; страховка: ' + str(tx.get('watchdog_active')), '33')
                elif tx.get('integrity_error'):
                    say('    Время не подтверждено: ' + str(tx['integrity_error']) + '; страховка: ' + str(tx.get('watchdog_active')), '33')
                elif 'remaining_seconds' in tx:
                    say('    До автоотката: ' + str(tx['remaining_seconds']) + ' с; страховка: ' + str(tx.get('watchdog_active')), '33')
        else:
            say('[ИНФО] ' + json.dumps(item, ensure_ascii=False), '36')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
