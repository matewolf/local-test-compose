#!/bin/sh

# containers="python-server-7000 python-server-8000 go-https-fileserver mock-assistant echo"
containers="mock-assistant"

usage() {
  cat <<'EOF'
Usage: call-container.sh [container-name]

Options:
  container-name   Optional. One of:
                   python-server-7000 | python-server-8000 |
                   go-https-fileserver | mock-assistant
                   Defaults to a random choice if omitted.
EOF
}

if [ "${1-}" = "-h" ] || [ "${1-}" = "--help" ]; then
  usage
  exit 0
fi

requested_choice=${1-}

random_choice() {
  count=0
  for c in $containers; do
    count=$((count + 1))
  done

  if command -v od >/dev/null 2>&1; then
    rand=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
  else
    rand=$(date +%s)
  fi

  idx=$((rand % count + 1))
  i=1
  for c in $containers; do
    if [ "$i" -eq "$idx" ]; then
      printf '%s\n' "$c"
      return
    fi
    i=$((i + 1))
  done
}

while :; do
  if [ -n "$requested_choice" ]; then
    choice=$requested_choice
  else
    choice=$(random_choice)
  fi

  case "$choice" in
    python-server-7000)
      echo "Calling '$choice' via curl..."
      curl -v "http://python-server-7000:7000/"
      ;;
    python-server-8000)
      echo "Calling '$choice' via curl..."
      curl -v "http://python-server-8000:8000/"
      ;;
    go-https-fileserver)
      echo "Calling '$choice' via curl..."
      curl -v --insecure "https://go-https-fileserver:9000/"
      ;;
    mock-assistant)
      echo "Calling '$choice' via curl..."
      curl -v -H "Content-Type: application/json" \
        -H "Connection: close" \
        --data "{\"message\": \"Hello, how are you?\"}" \
        "http://mock-assistant:3000/chat"
      ;;
    echo)
      echo "Calling '$choice' via curl..."
      curl -v --insecure "https://echo.free.beeceptor.com"
      ;;
    *)
      echo "Unknown container: $choice" >&2
      usage >&2
      exit 1
      ;;
  esac

  sleep 2
done
