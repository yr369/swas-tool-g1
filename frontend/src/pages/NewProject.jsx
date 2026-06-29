import { useNavigate } from "react-router-dom";
import { ScopeIntake } from "../components/ScopeIntake";

export function NewProject() {
  const navigate = useNavigate();

  return (
    <div style={{ maxWidth: 640 }}>
      <ScopeIntake onProjectCreated={(project) => navigate(`/projects/${project.id}`)} />
    </div>
  );
}
