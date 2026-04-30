import React from "react";
import ReactDOM from "react-dom/client";
import {
  Link,
  NavLink,
  Outlet,
  RouterProvider,
  createBrowserRouter,
  useParams,
} from "react-router";

import { getItem, getItems } from "./api/items";
import { useCounterStore } from "./store/counter";
import "./styles.css";

type AsyncState<T> = {
  data: T | null;
  error: string;
  loading: boolean;
};

function AppLayout() {
  const navItems = [
    { to: "/", label: "Home" },
    { to: "/dynamic", label: "Dynamic" },
    { to: "/state", label: "State" },
    { to: "/api-demo", label: "API Demo" },
    { to: "/form", label: "Form" },
  ];

  return (
    <div className="shell">
      <header className="hero">
        <p className="eyebrow">Go + React Single Binary</p>
        <h1>Web Template Playground</h1>
        <p className="lede">
          A compact example app that demonstrates routing, shared state, API calls,
          and form handling against the embedded Go backend.
        </p>
      </header>

      <div className="content-grid">
        <aside className="sidebar">
          <nav className="nav-list" aria-label="Examples">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  isActive ? "nav-link nav-link-active" : "nav-link"
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </aside>

        <main className="panel">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function HomePage() {
  const cards = [
    {
      title: "Dynamic Routes",
      body: "Fetch a list, navigate with URL params, and render a nested detail page.",
      to: "/dynamic",
    },
    {
      title: "Zustand State",
      body: "Share a counter across sibling components without extra providers.",
      to: "/state",
    },
    {
      title: "Axios Demo",
      body: "Show loading, error handling, and request cancellation against the Go API.",
      to: "/api-demo",
    },
    {
      title: "Controlled Form",
      body: "Validate fields, submit async, and surface user-friendly errors.",
      to: "/form",
    },
  ];

  return (
    <section className="stack">
      <div className="section-heading">
        <h2>Examples</h2>
        <p>Each route maps directly to a small, focused frontend pattern.</p>
      </div>

      <div className="card-grid">
        {cards.map((card) => (
          <Link key={card.to} className="card" to={card.to}>
            <h3>{card.title}</h3>
            <p>{card.body}</p>
          </Link>
        ))}
      </div>
    </section>
  );
}

type Item = {
  id: string;
  name: string;
  description: string;
};

function DynamicListPage() {
  const [state, setState] = React.useState<AsyncState<Item[]>>({
    data: null,
    error: "",
    loading: true,
  });

  React.useEffect(() => {
    const controller = new AbortController();

    setState({ data: null, error: "", loading: true });
    getItems(controller.signal)
      .then((items) => {
        setState({ data: items, error: "", loading: false });
      })
      .catch((error: unknown) => {
        if ((error as { code?: string }).code === "ERR_CANCELED") {
          return;
        }

        setState({
          data: null,
          error: "Failed to load items from /api/items.",
          loading: false,
        });
      });

    return () => controller.abort();
  }, []);

  return (
    <section className="stack">
      <div className="section-heading">
        <h2>Dynamic Route Demo</h2>
        <p>Routes under <code>/dynamic</code> read params and share layout state.</p>
      </div>

      {state.loading && <p className="notice">Loading items...</p>}
      {state.error && <p className="notice notice-error">{state.error}</p>}

      {state.data && (
        <div className="list">
          {state.data.map((item) => (
            <article className="list-row" key={item.id}>
              <div>
                <h3>{item.name}</h3>
                <p>{item.description}</p>
              </div>

              <div className="row-actions">
                <Link className="button button-secondary" to={`/dynamic/${item.id}`}>
                  Open
                </Link>
                <Link
                  className="button button-ghost"
                  to={`/dynamic/${item.id}/detail`}
                >
                  Nested Detail
                </Link>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function DynamicItemLayout() {
  const params = useParams();

  return (
    <section className="stack">
      <div className="section-heading">
        <h2>Item Route Layout</h2>
        <p>
          Current <code>:id</code>: <strong>{params.id}</strong>
        </p>
      </div>

      <div className="inline-actions">
        <Link className="button button-secondary" to="/dynamic">
          Back to List
        </Link>
        <Link className="button button-ghost" to="detail">
          Open Nested Detail
        </Link>
      </div>

      <Outlet />
    </section>
  );
}

function DynamicItemIndexPage() {
  const params = useParams();

  return (
    <div className="card card-static">
      <h3>Primary Detail View</h3>
      <p>
        This route renders at <code>/dynamic/{params.id}</code> and provides a stable
        layout for nested content.
      </p>
    </div>
  );
}

function DynamicItemDetailPage() {
  const params = useParams();

  return (
    <div className="card card-static">
      <h3>Nested Detail View</h3>
      <p>
        Nested child routes still read the same parent param. Current item:
        <strong> {params.id}</strong>.
      </p>
    </div>
  );
}

function CounterDisplay() {
  const count = useCounterStore((state) => state.count);

  return (
    <article className="card card-static">
      <h3>Shared Counter</h3>
      <p className="big-number">{count}</p>
      <p>Both panels below subscribe to the same Zustand store.</p>
    </article>
  );
}

function CounterControls() {
  const increment = useCounterStore((state) => state.increment);
  const decrement = useCounterStore((state) => state.decrement);

  return (
    <article className="card card-static">
      <h3>Controls</h3>
      <div className="inline-actions">
        <button className="button button-secondary" onClick={() => decrement()}>
          -1
        </button>
        <button className="button" onClick={() => increment()}>
          +1
        </button>
      </div>
    </article>
  );
}

function StateDemoPage() {
  return (
    <section className="stack">
      <div className="section-heading">
        <h2>Zustand State Demo</h2>
        <p>A minimal shared store with explicit actions.</p>
      </div>

      <div className="card-grid">
        <CounterDisplay />
        <CounterControls />
      </div>
    </section>
  );
}

function ApiDemoPage() {
  const [state, setState] = React.useState<AsyncState<Item>>({
    data: null,
    error: "",
    loading: false,
  });
  const controllerRef = React.useRef<AbortController | null>(null);

  const loadItem = React.useCallback(async (id: string) => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;

    setState({ data: null, error: "", loading: true });

    try {
      const item = await getItem(id, controller.signal);
      setState({ data: item, error: "", loading: false });
    } catch (error: unknown) {
      if ((error as { code?: string }).code === "ERR_CANCELED") {
        setState((current) => ({ ...current, loading: false, error: "Request cancelled." }));
        return;
      }

      setState({
        data: null,
        error: "Request failed. Try an existing item like alpha or beta.",
        loading: false,
      });
    }
  }, []);

  React.useEffect(() => {
    return () => controllerRef.current?.abort();
  }, []);

  return (
    <section className="stack">
      <div className="section-heading">
        <h2>Axios Demo</h2>
        <p>Click to load a record, trigger an error, or cancel an in-flight request.</p>
      </div>

      <div className="inline-actions">
        <button className="button" onClick={() => void loadItem("alpha")}>
          Load alpha
        </button>
        <button className="button button-secondary" onClick={() => void loadItem("missing")}>
          Load missing
        </button>
        <button
          className="button button-ghost"
          onClick={() => controllerRef.current?.abort()}
        >
          Cancel request
        </button>
      </div>

      {state.loading && <p className="notice">Loading request...</p>}
      {state.error && <p className="notice notice-error">{state.error}</p>}

      {state.data && (
        <article className="card card-static">
          <h3>{state.data.name}</h3>
          <p>{state.data.description}</p>
          <p>
            API payload id: <code>{state.data.id}</code>
          </p>
        </article>
      )}
    </section>
  );
}

type FormValues = {
  email: string;
  name: string;
  note: string;
};

function validateForm(values: FormValues) {
  const errors: Partial<Record<keyof FormValues, string>> = {};

  if (!values.name.trim()) {
    errors.name = "Name is required.";
  }

  if (!values.email.includes("@")) {
    errors.email = "Email must contain @.";
  }

  if (values.note.trim().length < 10) {
    errors.note = "Note must be at least 10 characters.";
  }

  return errors;
}

function FormDemoPage() {
  const [values, setValues] = React.useState<FormValues>({
    email: "",
    name: "",
    note: "",
  });
  const [errors, setErrors] = React.useState<Partial<Record<keyof FormValues, string>>>({});
  const [submitting, setSubmitting] = React.useState(false);
  const [submitted, setSubmitted] = React.useState<FormValues | null>(null);

  function updateField<K extends keyof FormValues>(key: K, value: FormValues[K]) {
    setValues((current) => ({ ...current, [key]: value }));
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const nextErrors = validateForm(values);
    setErrors(nextErrors);
    setSubmitted(null);

    if (Object.keys(nextErrors).length > 0) {
      return;
    }

    setSubmitting(true);
    await new Promise((resolve) => window.setTimeout(resolve, 500));
    setSubmitting(false);
    setSubmitted(values);
  }

  return (
    <section className="stack">
      <div className="section-heading">
        <h2>Controlled Form Demo</h2>
        <p>Explicit validation, async submit simulation, and visible field errors.</p>
      </div>

      <form className="form" onSubmit={handleSubmit}>
        <label className="field">
          <span>Name</span>
          <input
            value={values.name}
            onChange={(event) => updateField("name", event.target.value)}
          />
          {errors.name && <small className="field-error">{errors.name}</small>}
        </label>

        <label className="field">
          <span>Email</span>
          <input
            type="email"
            value={values.email}
            onChange={(event) => updateField("email", event.target.value)}
          />
          {errors.email && <small className="field-error">{errors.email}</small>}
        </label>

        <label className="field">
          <span>Note</span>
          <textarea
            rows={5}
            value={values.note}
            onChange={(event) => updateField("note", event.target.value)}
          />
          {errors.note && <small className="field-error">{errors.note}</small>}
        </label>

        <button className="button" disabled={submitting} type="submit">
          {submitting ? "Submitting..." : "Submit"}
        </button>
      </form>

      {submitted && (
        <article className="card card-static">
          <h3>Submitted Payload</h3>
          <pre>{JSON.stringify(submitted, null, 2)}</pre>
        </article>
      )}
    </section>
  );
}

const router = createBrowserRouter([
  {
    path: "/",
    element: <AppLayout />,
    children: [
      {
        index: true,
        element: <HomePage />,
      },
      {
        path: "dynamic",
        children: [
          {
            index: true,
            element: <DynamicListPage />,
          },
          {
            path: ":id",
            element: <DynamicItemLayout />,
            children: [
              {
                index: true,
                element: <DynamicItemIndexPage />,
              },
              {
                path: "detail",
                element: <DynamicItemDetailPage />,
              },
            ],
          },
        ],
      },
      {
        path: "state",
        element: <StateDemoPage />,
      },
      {
        path: "api-demo",
        element: <ApiDemoPage />,
      },
      {
        path: "form",
        element: <FormDemoPage />,
      },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
);
